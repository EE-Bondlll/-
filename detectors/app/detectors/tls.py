"""TLS 检测编排：仅扫描 https 资产，http 自动跳过。"""
import logging
logger = logging.getLogger(__name__)
from urllib.parse import urlparse

from app.schemas import Asset, ScanConfig, RiskRecord
from app.adapters.testssl import TestsslAdapter


def run_tls(assets: list[Asset], config: ScanConfig) -> list[RiskRecord]:
    adapter = TestsslAdapter()
    timeout = min(getattr(config, "timeout_sec", 30) or 30, 30)
    # testssl 是全量握手探测，30s 不够；放宽到 240s（仍受非破坏约束，仅探测连接）
    scan_timeout = max(timeout * 16, 600)
    results: list[RiskRecord] = []
    for asset in assets:
        url = getattr(asset, "url", None)
        if not url:
            continue
        if urlparse(url).scheme.lower() != "https":
            continue  # 非 HTTPS 资产不属本检测器
        try:
            results.extend(adapter.scan(url, timeout_sec=scan_timeout))
        except Exception as e:
            logger.warning("tls scan failed for %s: %s", url, e)
            continue
    return results

