from app.utils.ratelimit import limiter
from urllib.parse import urlparse
from app.adapters.base import BaseAdapter
from app.schemas import Asset, ScanConfig, RiskRecord

class SubfinderAdapter(BaseAdapter):
    tool_name = "subfinder"

    def run_domains(self, domains: list[str], config: ScanConfig) -> list[str]:
        """输入主域列表，输出子域（含主域本身）"""
        if not self.check_available():
            return domains                      # 工具缺失时降级：至少返回主域
        found = set(domains)
        for d in domains:
            limiter.wait(d)
            cmd = ["subfinder", "-d", d, "-silent", "-timeout", str(config.timeout_sec)]
            _, stdout, _ = self._exec(cmd, config.timeout_sec)
            for line in stdout.splitlines():
                line = line.strip()
                if line and "." in line:
                    found.add(line)
        return sorted(found)

    # 以下两个抽象方法本适配器用不到，留空实现
    def build_cmd(self, asset, config): ...
    def parse(self, stdout, asset) -> list[RiskRecord]: return []