import json
from urllib.parse import urlparse
from app.adapters.base import BaseAdapter
from app.schemas import Asset, ScanConfig, RiskRecord

class KatanaAdapter(BaseAdapter):
    tool_name = "katana"

    def crawl(self, asset: Asset, config: ScanConfig, limiter) -> list[str]:
        self.check_available()
        host = urlparse(asset.url).hostname or asset.url
        limiter.wait(host)
        cmd = [self.bin_path or "katana", "-u", asset.url,
        "-jsonl", "-kf", "all", "-silent",
        "-timeout", str(config.timeout_sec),
        "-rate-limit", str(config.rate_limit_qps),
        "-or"]
        _, stdout, _ = self._exec(cmd, timeout_sec=config.timeout_sec * 3)
        urls = set()
        for line in stdout.splitlines():
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            ep = j.get("request", {}).get("endpoint") or j.get("endpoint")
            if ep:
                urls.add(ep)
        return sorted(urls)

    def build_cmd(self, asset, config): ...
    def parse(self, stdout, asset) -> list[RiskRecord]: return []