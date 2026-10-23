import httpx
from datetime import datetime

from app.adapters.base import BaseAdapter
from app.schemas import Asset, ScanConfig, RiskRecord, Evidence, Severity
from app.utils.signature import make_signature

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("缺失 HSTS，存在协议降级风险", Severity.medium),
    "Content-Security-Policy": ("缺失 CSP，存在 XSS 缓解不足风险", Severity.low),
    "X-Frame-Options": ("缺失点击劫持防护头", Severity.low),
    "X-Content-Type-Options": ("缺失 MIME 嗅探防护头", Severity.low),
}


class HeadersAdapter(BaseAdapter):
    tool_name = "httpx"          # 复用 python httpx 库发请求（注意：这是 Python 库，非 Go 工具）

    def check(self, asset: Asset, config: ScanConfig) -> list[RiskRecord]:
        now = datetime.now().astimezone()
        try:
            r = httpx.get(asset.url, timeout=config.timeout_sec,
                          follow_redirects=True, verify=False)
        except Exception:
            return []
        risks = []
        for h, (msg, sev) in SECURITY_HEADERS.items():
            if h not in r.headers:
                risks.append(RiskRecord(
                    asset_url=asset.url, category="weak_config", severity=sev,
                    title=f"响应缺失安全头 {h}", description=msg,
                    evidence=Evidence(response_sample=str(dict(r.headers))[:2000]),
                    raw_output="", tool="headers", template=f"header:{h}",
                    first_seen=now, last_seen=now,
                    signature=make_signature(asset.url, "weak_config",
                                             f"响应缺失安全头 {h}", f"header:{h}"),
                ))
        return risks

    def build_cmd(self, asset, config): return []
    def parse(self, stdout, asset): return []