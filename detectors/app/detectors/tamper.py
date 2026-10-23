"""篡改检测器：基线哈希比对 + 隐藏 iframe/黑页关键词直检 + 验签式证据。

detail 约定：tamper:{新内容sha256前8位} —— 仅作签名输入，明文存于 description 与 raw_output。
记录字段严格遵循 contracts/risk_schema.json（14 字段，无 detail）。
"""
import hashlib
import json
import re
import difflib
from datetime import datetime, timezone

import httpx

from app.schemas import Asset, ScanConfig, RiskRecord, Evidence, Category, Severity
from app.utils.signature import make_signature
from app.utils.baseline import BaselineStore
from app.utils.ratelimit import limiter

# 黑页/篡改关键词（命中即升为 high，不单独触发）
TAMPER_KEYWORDS = [
    "hacked by", "owned by", "defaced", "pwned",
    "黑页", "网站已被", "你被入侵", "webshell",
]

_HIDDEN_IFRAME = re.compile(
    r"<iframe\b[^>]*?(display\s*:\s*none|visibility\s*:\s*hidden|"
    r"width\s*=\s*[\"']?0|height\s*=\s*[\"']?0)[^>]*>",
    re.IGNORECASE,
)

_DYNAMIC_VALUE = re.compile(
    r"(<input[^>]*?(?:token|nonce|csrf)[^>]*?value\s*=\s*([\"']))[^\"']*\2",
    re.IGNORECASE,
)

def extract_features(html: str) -> dict:
    """从页面提取可比对特征（先归一化动态值，再取哈希）。"""
    html = _DYNAMIC_VALUE.sub(r"\1__NORM__\2", html)
    title_m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return {
        "sha256": hashlib.sha256(html.encode("utf-8", errors="ignore")).hexdigest(),
        "length": len(html),
        "script_tags": len(re.findall(r"<script\b", html, re.IGNORECASE)),
        "title": (title_m.group(1).strip() if title_m else "")[:200],
        "hidden_iframe_tags": _HIDDEN_IFRAME.findall(html)[:3],
    }


def make_diff_excerpt(old_html: str, new_html: str, max_lines: int = 20) -> str:
    """生成 HTML 行级差异摘要。基线只存哈希，此处以哈希变化说明代替全文 diff。"""
    diff = difflib.unified_diff(
        old_html.splitlines(), new_html.splitlines(),
        lineterm="", n=1,
    )
    lines = [ln for ln in diff if ln[:1] in "+-" and not ln.startswith(("+++", "---"))]
    return "\n".join(lines[:max_lines])


def run_tamper(assets: list[Asset], config: ScanConfig,
               store: BaselineStore | None = None) -> list[RiskRecord]:
    store = store or BaselineStore()
    timeout = min(getattr(config, "timeout_sec", 30) or 30, 30)
    results: list[RiskRecord] = []

    for asset in assets:
        url = getattr(asset, "url", None)
        if not url:
            continue
        limiter.wait(host=url.split("/")[2]) # 复用全局 QPS 限制器（≤5 QPS）
        try:
            resp = httpx.get(url, timeout=timeout, follow_redirects=True)
            new_html = resp.text
        except Exception:
            continue  # 页面不可达不属篡改，由存活探测环节负责

        feat = extract_features(new_html)
        baseline = store.get(url)

        if baseline is None:
            # 首次见到该页面：只建档，不报
            store.put(url, feat)
            continue

        changes = []
        if feat["sha256"] != baseline["sha256"]:
            changes.append("content_hash")
        if feat["script_tags"] != baseline.get("script_tags", 0):
            changes.append("script_count")
        if feat["title"] != baseline.get("title", ""):
            changes.append("title")

        new_hidden_iframe = bool(feat["hidden_iframe_tags"]) and not baseline.get("hidden_iframe_tags")
        keyword_hits = [k for k in TAMPER_KEYWORDS if k in new_html.lower()]

        if not changes and not new_hidden_iframe:
            continue  # 无变化

        # ★ 契约：detail 仅作签名输入，不存储
        sig_detail = f"tamper:{feat['sha256'][:8]}"
        severity = Severity.high if (new_hidden_iframe or keyword_hits) else Severity.medium
        title = "页面被植入隐藏 iframe" if new_hidden_iframe else "页面内容疑似被篡改"
        diff_text = ""
        if "content_hash" in changes:
            diff_text = f"hash {baseline['sha256'][:12]}... -> {feat['sha256'][:12]}..."

        now = datetime.now(timezone.utc).isoformat()
        results.append(RiskRecord(
            asset_url=url,
            category=Category.tamper,
            severity=severity,
            title=title,
            description=(
                f"基线比对异常:{changes}; 新哈希前缀:{feat['sha256'][:8]}"
                + (f"; 隐藏iframe:{feat['hidden_iframe_tags']}" if new_hidden_iframe else "")
                + (f"; 黑页关键词:{keyword_hits}" if keyword_hits else "")
            ),
            evidence=Evidence(
                request_sample=f"GET {url}",
                response_sample=diff_text or f"changes={changes}",
                matched_context=f"hash {baseline['sha256'][:12]}... -> {feat['sha256'][:12]}...",
            ),
            raw_output=json.dumps({
                "detail": sig_detail,
                "old_hash": baseline["sha256"],
                "new_hash": feat["sha256"],
                "changes": changes,
                "hidden_iframe_tags": feat["hidden_iframe_tags"],
                "keyword_hits": keyword_hits,
            }, ensure_ascii=False),
            tool="tamper",
            template="tamper:hidden-iframe" if has_hidden_iframe else f"tamper:{feat['sha256'][:8]}",
            signature=make_signature(url, "tamper", title, sig_detail),
            first_seen=now,
            last_seen=now,
        ))
    return results