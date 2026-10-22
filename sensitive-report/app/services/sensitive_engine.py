"""敏感信息检测引擎核心：抓取页面 → 按规则匹配 → 收集上下文 → 脱敏 → 生成 leak 记录。

匹配顺序：关键词 → 正则 → 文件类型（URL 后缀）。
所有命中内容在 evidence.matched_context 中脱敏后输出。
"""
import hashlib
import re
from datetime import datetime, timezone

import httpx

from .. import config, redact


def _make_signature(url: str, rule_name: str, matched: str) -> str:
    return hashlib.sha256(f"{url}|leak|{rule_name}|{matched[:64]}".encode()).hexdigest()


def _collect_context(text: str, start: int, end: int, span: int = 120) -> str:
    """取命中位置前后 span 个字符作为上下文。"""
    s = max(0, start - span)
    e = min(len(text), end + span)
    return text[s:e].replace("\n", " ").strip()


def scan_url(url: str, rules: list[dict], client: httpx.Client) -> list[dict]:
    """对单个 URL 抓取并匹配规则，返回 leak 风险记录列表。

    rules: [{"type":"keyword|regex|file_type","name":...,"pattern":...,"severity":...}]
    """
    risks = []
    # 1) 文件类型规则：直接按 URL 后缀命中（不必抓内容）
    for rule in rules:
        if rule.get("type") != "file_type":
            continue
        ext = rule["pattern"]
        if ext and url.lower().endswith(ext.lower()):
            risks.append(_build_risk(url, rule, matched=f"URL 路径命中文件类型 {ext}",
                                     context=f"访问 {url} 时直接返回了 {ext} 类型文件内容"))
            return risks  # 敏感文件整文件即泄露，直接返回，不再做内容匹配

    # 2) 抓取页面内容
    try:
        resp = client.get(url, timeout=config.REQUEST_TIMEOUT, follow_redirects=True,
                          headers={"User-Agent": "InspectionBot/1.0 (non-destructive)"})
        body = resp.text
    except Exception as e:
        return [_build_risk(url, {"name": "抓取失败", "severity": "low"},
                            matched="fetch_error", context=f"抓取失败：{type(e).__name__}: {e}")]

    # 3) 关键词匹配
    for rule in rules:
        if rule.get("type") != "keyword":
            continue
        kw = rule["pattern"]
        if not kw:
            continue
        for m in re.finditer(re.escape(kw), body, re.IGNORECASE):
            ctx = _collect_context(body, m.start(), m.end())
            risks.append(_build_risk(url, rule, matched=kw, context=ctx))

    # 4) 正则匹配
    for rule in rules:
        if rule.get("type") != "regex":
            continue
        try:
            pat = re.compile(rule["pattern"])
        except re.error:
            continue
        for m in pat.finditer(body):
            ctx = _collect_context(body, m.start(), m.end())
            risks.append(_build_risk(url, rule, matched=m.group(0), context=ctx))

    return risks


def _build_risk(url: str, rule: dict, matched: str, context: str) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    name = rule.get("name", rule.get("type", "rule"))
    severity = rule.get("severity", "medium")
    return {
        "asset_url": url,
        "category": "leak",
        "severity": severity,
        "title": f"敏感信息泄露：{name}",
        "description": f"命中规则「{name}」，匹配内容已脱敏",
        "evidence": {
            "request_sample": f"GET {url} HTTP/1.1",
            "response_sample": "(已脱敏)",
            "matched_context": redact.redact(context),
        },
        "raw_output": '{}',
        "tool": "sensitive-engine",
        "template": f"rule:{rule.get('type','rule')}:{name}",
        "first_seen": now,
        "last_seen": now,
        "status": "active",
        "signature": _make_signature(url, name, matched),
    }


# ---------- gitleaks 可选封装 ----------

def gitleaks_available() -> bool:
    """系统是否安装了 gitleaks 二进制（未安装则静默降级）。"""
    import shutil
    return shutil.which("gitleaks") is not None


def run_gitleaks_on_path(target_path: str) -> list[dict]:
    """对本地目录/文件跑 gitleaks detect，解析 JSON 输出为 leak 风险记录。

    gitleaks 不存在时返回空列表（不影响主流程）。
    """
    import json
    import subprocess
    if not gitleaks_available():
        return []
    try:
        proc = subprocess.run(
            ["gitleaks", "detect", "--no-git", "--format", "json", "--source", target_path],
            capture_output=True, text=True, timeout=60,
        )
        findings = json.loads(proc.stdout or "[]")
    except Exception:
        return []
    out = []
    now = datetime.now(timezone.utc).isoformat()
    for f in findings:
        rule = {"name": f.get("RuleID", "gitleaks"), "severity": "high"}
        out.append({
            "asset_url": f"gitleaks:{f.get('File', target_path)}",
            "category": "leak",
            "severity": "critical",
            "title": f"gitleaks 命中密钥泄露：{f.get('RuleID')}",
            "description": f"文件 {f.get('File')} 行 {f.get('StartLine')} 命中",
            "evidence": {"matched_context": redact.redact(f.get("Secret", ""))},
            "raw_output": json.dumps(f, ensure_ascii=False),
            "tool": "gitleaks",
            "template": f"gitleaks:{f.get('RuleID')}",
            "first_seen": now, "last_seen": now, "status": "active",
            "signature": _make_signature(target_path, f.get("RuleID", ""), f.get("Secret", "")),
        })
    return out

