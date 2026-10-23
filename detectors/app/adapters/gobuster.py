import os
import re
from urllib.parse import urlparse
from app.adapters.base import BaseAdapter
from app.schemas import Asset, ScanConfig, RiskRecord

WORDLIST = os.path.expanduser("~/wordlists/common-small.txt")
LINE_RE = re.compile(r"^\s*/?(\S+)\s+\(Status:\s*(\d+)\)")
SKIP_CODES = {301, 302, 400, 401, 403, 404, 500}

class GobusterAdapter(BaseAdapter):
    tool_name = "gobuster"

    def dir_scan(self, asset: Asset, config: ScanConfig, limiter) -> list[tuple[str, int]]:
        if not self.check_available():
            return []
        host = urlparse(asset.url).hostname or asset.url
        limiter.wait(host)
        cmd = [self.bin_path or "gobuster", "dir", "-u", asset.url,
               "-w", WORDLIST, "-t", "5", "-q", "-k",
               "--timeout", f"{config.timeout_sec}s"]      # ← 去掉 --excludestatus
        _, stdout, _ = self._exec(cmd, timeout_sec=config.timeout_sec * 6)
        SKIP = {301, 302, 400, 401, 403, 404}              # ← 在这里过滤噪声状态码
        hits = []
        for line in stdout.splitlines():
            m = LINE_RE.match(line)
            if not m:
                continue
            code = int(m.group(2))
            if code in SKIP_CODES:
                continue
            path = m.group(1)
            if not path.startswith("/"):          # 补回斜杠，保证 URL 拼接正确
               path = "/" + path
            hits.append((path, code))
        return hits

    def build_cmd(self, asset, config): ...
    def parse(self, stdout, asset) -> list[RiskRecord]: return []