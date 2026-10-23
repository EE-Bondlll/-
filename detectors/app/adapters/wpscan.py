import json
from datetime import datetime

from app.adapters.base import BaseAdapter
from app.schemas import Asset, ScanConfig, RiskRecord, Evidence, Severity
from app.utils.signature import make_signature


class WpscanAdapter(BaseAdapter):
    tool_name = "wpscan"
    destructive_forbidden = ["--passwords", "--usernames", "--enumerate", "u"]  # 禁爆破类枚举

    def run_wp(self, asset: Asset, config: ScanConfig) -> list[RiskRecord]:
        if not self.check_available():
            return []
        now = datetime.now().astimezone()
        cmd = [self.bin_path, "--url", asset.url,
               "--no-banner", "--format", "json",
               "--max-threads", str(config.rate_limit_qps),
               "--request-timeout", str(config.timeout_sec),
               "--disable-tls-checks"]          # 自签名 https 靶场需要
        _, stdout, _ = self._exec(cmd, timeout_sec=config.timeout_sec * 4)
        try:
            j = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        risks = []
        ver = (j.get("version") or {}).get("number")
        # 1. 核心版本漏洞（无 token 时 vulnerabilities 可能为空，属正常）
        for v in (j.get("version") or {}).get("vulnerabilities") or []:
            title = v.get("title") or f"WordPress {ver} 漏洞"
            risks.append(self._mk(asset.url, title, v.get("references"),
                                  f"wpscan:WordPress {ver}", now))
        # 2. 插件漏洞
        for pname, pdata in (j.get("plugins") or {}).items():
            for v in (pdata.get("vulnerabilities") or []):
                title = v.get("title") or f"插件 {pname} 漏洞"
                risks.append(self._mk(asset.url, title, v.get("references"),
                                      f"wpscan:plugin:{pname}", now))
        return risks

    def _mk(self, url, title, refs, detail, now) -> RiskRecord:
        ref = (refs or {}).get("url") or []
        return RiskRecord(
            asset_url=url, category="vuln",
            severity=Severity.high,                 # wpscan 漏洞默认 high，后续可按 CVSS 细化
            title=title,
            description=title,
            evidence=Evidence(matched_context="; ".join(ref[:3]) if ref else None),
            raw_output="",
            tool="wpscan", template=detail,
            first_seen=now, last_seen=now,
            signature=make_signature(url, "vuln", title, detail),
        )

    def build_cmd(self, asset, config): return []
    def parse(self, stdout, asset): return []