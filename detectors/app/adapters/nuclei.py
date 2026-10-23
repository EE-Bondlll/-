import base64
import json
import os
from datetime import datetime, timezone

from app.adapters.base import BaseAdapter
from app.schemas import Asset, ScanConfig, RiskRecord, Evidence, Severity
from app.utils.signature import make_signature

SEV_MAP = {          # nuclei 级别 → 契约级别（对齐任务书取值）
    "critical": Severity.critical, "high": Severity.high,
    "medium": Severity.medium, "low": Severity.low,
    "info": Severity.low,
}


def _b64_or_raw(s):
    """nuclei v3 的 request/response 是 base64；兼容明文"""
    if not s:
        return None
    try:
        return base64.b64decode(s).decode("utf-8", errors="replace")
    except Exception:
        return s


class NucleiAdapter(BaseAdapter):
    tool_name = "nuclei"
    # 非破坏硬要求：禁用的参数（守卫在 base.guard）
    destructive_forbidden = ["-itags", "-tags", "fuzzing", "dos", "intrusive"]

    TEMPLATES_DIR = os.path.expanduser("~/nuclei-templates")

    def run(self, asset, config):
        if not self.check_available():
            raise ToolNotFoundError(f"{self.tool_name} 未安装")
        cmd = self.build_cmd(asset, config)
        self.guard(cmd)
        code, stdout, _ = self._exec(cmd, timeout_sec=1800)   # 局部值,不动 config
        if code != 0 and not stdout:
            return []
        return self.parse(stdout, asset)


    _CVE_WORTHY_CMS = {"wordpress", "joomla", "drupal"}

    def build_cmd(self, asset, config) -> list[str]:
        url = asset.url
        qps = getattr(config, "rate_limit_qps", None) or 5
        timeout = getattr(config, "timeout_sec", None) or 30

        # 指纹决定模板范围（任务书 4.4：按指纹过滤模板）
        fp = getattr(asset, "fingerprint", None) or {}
        cms = (fp.get("cms") or "").lower()

        template_dirs = [os.path.join(self.TEMPLATES_DIR, "http", "misconfiguration")]
        if cms in self._CVE_WORTHY_CMS:
        # 仅已知 CMS 才跑全量 cves（避免单站扫数百模板耗时 10min+）；
        # 未知指纹/静态站保守只跑 misconfiguration（弱配置/安全头），秒级完成
            template_dirs.append(os.path.join(self.TEMPLATES_DIR, "http", "cves"))

        cmd = [
            self.bin_path,
            "-u", url,
            "-duc", "-jsonl", "-silent", "-nc",
            "-c", "25",              # 并发模板数（提速：默认不设时对单 URL 并发不足）
            "-etags", "dos,intrusive",
            "-rl", str(qps),
            "-timeout", str(timeout),
        ]
        for d in template_dirs:
            cmd += ["-t", d]
        return cmd

    def parse(self, stdout: str, asset: Asset) -> list[RiskRecord]:
        risks = []
        now = datetime.now(timezone.utc)
        for line in stdout.splitlines():
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = j.get("info", {})
            title = info.get("name") or j.get("template-id") or "nuclei finding"
            template = j.get("template-id") or info.get("template") or ""
            matched = j.get("matched-at") or asset.url
            sev = SEV_MAP.get((info.get("severity") or "low").lower(), Severity.low)

            desc = info.get("description") or f"命中 Nuclei 模板 {template}"
            risks.append(RiskRecord(
                asset_url=matched,
                category="vuln",
                severity=sev,
                title=title,
                description=desc,
                evidence=Evidence(
                    request_sample=_b64_or_raw(j.get("request")),
                    response_sample=_b64_or_raw(j.get("response")),
                    matched_context=info.get("description"),
                ),
                raw_output=json.dumps(j, ensure_ascii=False),
                tool="nuclei",
                template=template,                       # detail 明文落 template 字段（契约已有）
                first_seen=now,
                last_seen=now,
                signature=make_signature(matched, "vuln", title, template),  # detail = template-id
            ))
        return risks