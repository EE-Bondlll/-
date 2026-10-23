import logging
from abc import ABC, abstractmethod
from app.schemas import Asset, ScanConfig, RiskRecord
from app.utils.pathtool import resolve_tool

logger = logging.getLogger("adapter")


class ToolNotFoundError(Exception):
    pass


class BaseAdapter(ABC):
    tool_name: str = ""
    destructive_forbidden: list[str] = []

    def __init__(self):
        self.bin_path = resolve_tool(self.tool_name)   # 实例化即解析

    def check_available(self) -> bool:
        return self.bin_path is not None

    @abstractmethod
    def build_cmd(self, asset: Asset, config: ScanConfig) -> list[str]: ...

    @abstractmethod
    def parse(self, stdout: str, asset: Asset) -> list[RiskRecord]: ...

    def guard(self, cmd: list[str]) -> None:
        for bad in self.destructive_forbidden:
            if bad in cmd:
                raise ValueError(f"检测到禁用参数 {bad}，违反非破坏原则")

    def _exec(self, cmd: list[str], timeout_sec: int):
        from app.utils.runner import run_cmd
        code, stdout, stderr = run_cmd(cmd, timeout_sec=timeout_sec)
        if code != 0:
            logger.warning("%s 退出码 %s: %s", self.tool_name, code, stderr[:300])
        return code, stdout, stderr

    def run(self, asset: Asset, config: ScanConfig) -> list[RiskRecord]:
        if not self.check_available():
            raise ToolNotFoundError(f"{self.tool_name} 未安装")
        cmd = self.build_cmd(asset, config)
        self.guard(cmd)
        code, stdout, _ = self._exec(cmd, timeout_sec=config.timeout_sec)
        if code != 0 and not stdout:
            return []
        return self.parse(stdout, asset)