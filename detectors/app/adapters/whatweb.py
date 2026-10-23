import json
import os
import tempfile

from app.adapters.base import BaseAdapter
from app.schemas import Asset, ScanConfig, RiskRecord

# 常见 CMS 的 whatweb 插件名 → 统一小写 key（契约 fingerprint.cms 的取值）
CMS_MAP = {
    "WordPress": "wordpress",
    "Joomla": "joomla",
    "Drupal": "drupal",
    "Magento": "magento",
    "Discuz": "discuz",
}

# 常见 Web 服务器插件名 → fingerprint.server 取值
SERVER_MAP = {
    "Apache": "apache",
    "nginx": "nginx",
    "Microsoft-IIS": "iis",
    "LiteSpeed": "litespeed",
    "openresty": "openresty",
}


class WhatwebAdapter(BaseAdapter):
    tool_name = "whatweb"

    def fingerprint(self, asset: Asset, config: ScanConfig) -> dict:
        """对单个 URL 做指纹识别，返回契约 fingerprint 字典"""
        if not self.check_available():
            return {}

        # whatweb 的 JSON 必须写文件，不能 stdout：用临时文件
        fd, logfile = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            cmd = [self.bin_path, asset.url,
                   "-a", "1",                       # 被动模式
                   "--log-json", logfile,
                   "--color=never"]
            _, stdout, _ = self._exec(cmd, timeout_sec=config.timeout_sec * 2)

            with open(logfile, encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
        finally:
            os.unlink(logfile) if os.path.exists(logfile) else None

        return self._normalize(data, asset)

    def _normalize(self, data, asset: Asset) -> dict:
        """whatweb 原始 JSON → 契约 fingerprint"""
        fp: dict = {}
        # data 是数组，取第一条（单 URL 扫描只有一条）
        plugins = (data[0] if isinstance(data, list) and data else {}).get("plugins", {})

        # 1. CMS + version
        for w_name, key in CMS_MAP.items():
            if w_name in plugins:
                fp["cms"] = key
                vers = plugins[w_name].get("version") or []
                if vers:
                    fp["version"] = vers[0]
                break

        # 2. server（whatweb 里服务器插件名即组件名）
        for w_name, key in SERVER_MAP.items():
            if w_name in plugins:
                fp["server"] = key
                vers = plugins[w_name].get("version") or []
                if vers and "server_version" not in fp:
                    fp["server_version"] = vers[0]
                break

        # 3. 标题兜底（whatweb 有 Title 插件时顺手带上，供上层展示）
        title = plugins.get("Title", {}).get("string") or []
        if title and not asset.title:
            asset.title = title[0]

        return fp

    # BaseAdapter 抽象方法占位（本适配器不走 run() 主流程）
    def build_cmd(self, asset: Asset, config: ScanConfig) -> list[str]:
        return []

    def parse(self, stdout: str, asset: Asset) -> list[RiskRecord]:
        return []