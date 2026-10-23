"""testssl.sh 适配器：TLS/SSL 配置弱项检测（纯连接探测，非破坏）。

detail 约定：testssl:{finding-id}（仅作签名输入，明文存于 template/description）。
"""
import hashlib
import json
import os
from datetime import datetime, timezone

from app.adapters.base import BaseAdapter
from app.schemas import Asset, ScanConfig, RiskRecord, Evidence, Severity
from app.utils.signature import make_signature

SEV_MAP = {
    "CRITICAL": Severity.critical, "HIGH": Severity.high,
    "MEDIUM": Severity.medium, "LOW": Severity.low,
    "WARN": Severity.medium,
}
SKIP_SEV = {"OK", "INFO", "DEBUG"}


def _iter_findings(obj):
    """testssl JSON 结构随版本有差异，递归收集所有含 severity+id 的节点。"""
    if isinstance(obj, dict):
        if "severity" in obj and "id" in obj:
            yield obj
        for v in obj.values():
            yield from _iter_findings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_findings(v)

def _out_json(url: str) -> str:
    return f"/tmp/testssl_{hashlib.sha256(url.encode()).hexdigest()[:12]}.json"


class TestsslAdapter(BaseAdapter):
    tool_name = "testssl.sh"
    # testssl 只发探测连接，无破坏参数需要禁
    destructive_forbidden = []

    def build_cmd(self, asset, config) -> list[str]:
        url = getattr(asset, "url", asset)
        out_json = _out_json(url)            # ← 统一入口
        cmd = [self.bin_path, "--quiet"]     # --quiet 若之前验证报错过就删掉
        cmd.append(f"--jsonfile={out_json}")
        cmd.append(url)
        return cmd

    def scan(self, url: str, timeout_sec: int = 240) -> list[RiskRecord]:
        """testssl 通过 -oJ 写文件，需自定义执行流程（父类 run 只解析 stdout）。"""
        out_json = _out_json(url)
        for f in (out_json,):
            if os.path.exists(f):
                os.remove(f)
        cmd = self.build_cmd(url, out_json)
        code, stdout, stderr = self._exec(cmd, timeout_sec=timeout_sec)
        if not os.path.exists(out_json):
            raise RuntimeError(f"testssl 未产出 JSON：{stderr[:300]}")
        with open(out_json, encoding="utf-8") as f:
            data = json.load(f)
        os.remove(out_json)
        return self.parse(data, url)

    def parse(self, data, url: str) -> list[RiskRecord]:
        risks = []
        now = datetime.now(timezone.utc).isoformat()
        for f in _iter_findings(data):
            sev_raw = (f.get("severity") or "").upper()
            if sev_raw in SKIP_SEV:
                continue
            fid = f.get("id") or hashlib.sha256(
                json.dumps(f, sort_keys=True).encode()).hexdigest()[:12]
            sev = SEV_MAP.get(sev_raw, Severity.low)
            title = f.get("headline") or fid
            sig_detail = f"testssl:{fid}"
            risks.append(RiskRecord(
                asset_url=url,
                category="weak_config",
                severity=sev,
                title=f"TLS弱配置: {title}",
                description=f"testssl 命中 {fid}（{sev_raw}）；detail={sig_detail}",
                evidence=Evidence(
                    request_sample=f"testssl.sh {url}",
                    response_sample=json.dumps(f, ensure_ascii=False)[:800],
                    matched_context=sig_detail,
                ),
                raw_output=json.dumps(f, ensure_ascii=False),
                tool="testssl",
                template=fid,
                signature=make_signature(url, "weak_config", f"TLS弱配置: {title}", sig_detail),
                first_seen=now,
                last_seen=now,
            ))
        return risks