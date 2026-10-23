import json, tempfile, os
from app.adapters.base import BaseAdapter
from app.schemas import Asset, ScanConfig, RiskRecord
from urllib.parse import urlparse

class HttpxAdapter(BaseAdapter):
    tool_name = "httpx"

    def probe(self, hosts: list[str], config: ScanConfig) -> list[Asset]:
        """子域列表 → 存活资产（url/status_code/title/初步 tech）"""
        if not hosts:
            return []
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(hosts))
            listfile = f.name
        try:
            cmd = ["httpx", "-l", listfile, "-status-code", "-title",
                   "-tech-detect", "-json", "-silent", "-timeout", str(config.timeout_sec)]
            _, stdout, _ = self._exec(cmd, timeout_sec=config.timeout_sec * max(1, len(hosts) // 10))
        finally:
            os.unlink(listfile)

        assets = []
        for line in stdout.splitlines():
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = j.get("url")
            if not url:
                continue
            assets.append(Asset(
                url=url,
                host=j.get("host") or urlparse(url).hostname,
                status_code=j.get("status_code"),
                title=j.get("title"),
                fingerprint={},          # 阶段15由 whatweb 补全
            ))
        return assets

    def build_cmd(self, asset, config): ...
    def parse(self, stdout, asset) -> list[RiskRecord]: return []