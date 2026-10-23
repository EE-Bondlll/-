import hashlib
import re
import httpx
from urllib.parse import urlparse

from app.schemas import ScanRequest, DiscoveryResponse, Asset, ScanConfig
from app.adapters.subfinder import SubfinderAdapter
from app.adapters.httpx_probe import HttpxAdapter
from app.adapters.katana import KatanaAdapter
from app.adapters.gobuster import GobusterAdapter
from app.utils.ratelimit import limiter
from app.adapters.whatweb import WhatwebAdapter

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>",
                       re.IGNORECASE | re.DOTALL)

# 任务书 1.2：目录与备份文件探测。命中的 URL 作为资产输出（fingerprint 标
# sensitive_file），供 C 侧敏感引擎消费；本服务不产生 category=leak 的风险记录。
SENSITIVE_PATHS = [
    "/.env.bak", "/.env", "/.git/config", "/config.bak",
    "/config.php.bak", "/db.sql", "/backup.zip", "/www.zip",
]

# 任务书 1.3：whatweb 哑火时的 URL 特征兜底
def _guess_cms_from_url(url: str) -> dict:
    u = url.lower()
    if ("/wp-content/" in u or "/wp-includes/" in u
            or "wp-login" in u or "wp-admin" in u):
        return {"cms": "wordpress"}
    if "/sites/default/files/" in u:
        return {"cms": "drupal"}
    if "/media/system/" in u or "option=com_" in u:
        return {"cms": "joomla"}
    return {}


def _probe(url: str, timeout: int = 15):
    """抓取页面，返回 (page_hash, status_code, title)；失败返回 (None, None, None)。

    修复点：原先只返回 hash，status_code/title 被丢弃（契约 2.4 要求三字段）。
    """
    try:
        r = httpx.get(url, timeout=timeout, follow_redirects=True)
    except Exception:
        return None, None, None
    title = None
    m = _TITLE_RE.search(r.text[:8192])      # 只看前 8KB，提速
    if m:
        title = " ".join(m.group(1).split())[:200]
    return hashlib.sha256(r.content).hexdigest(), r.status_code, title


def _fill_fingerprints(assets: list[Asset], config: ScanConfig) -> None:
    """每 host 只跑一次 whatweb；cms 为空时叠加 URL 特征兜底。

    修复点：原代码的调用位置在 return 之后（死代码），且整组共享同一个
    dict 引用——这里改为每资产 copy 后再合并，避免互相污染。
    """
    whatweb = WhatwebAdapter()
    by_host: dict[str, list[Asset]] = {}
    for a in assets:
        by_host.setdefault(a.host or a.url, []).append(a)
    for host, group in by_host.items():
        fp = dict(whatweb.fingerprint(group[0], config) or {})
        for a in group:
            merged = dict(a.fingerprint or {})   # ← 先保留已有标记(sensitive_file 等)
            for k, v in fp.items():
                merged.setdefault(k, v)          # ← whatweb 只补空位,不覆盖
            if not merged.get("cms"):
                merged.update(_guess_cms_from_url(a.url))
            a.fingerprint = merged


def run_discovery(req: ScanRequest) -> DiscoveryResponse:
    config = req.config
    PRIVATE_PREFIXES = ("127.", "192.168.", "10.", "172.")

    # 1. 种子 URL 完整入池（保留端口）——本地靶场全靠这一步
    url_pool: dict[str, Asset] = {a.url: a for a in req.assets}

    # 2. 仅对公网裸域做子域枚举 + 存活探测
    sub, hx = SubfinderAdapter(), HttpxAdapter()
    for a in req.assets:
        host = urlparse(a.url).hostname or a.url
        if host == "localhost" or host.startswith(PRIVATE_PREFIXES):
            continue
        for live in hx.probe(sub.run_domains([host], config), config):
            url_pool.setdefault(live.url, live)

    # 3. katana 爬取 + gobuster 目录探测
    katana, gobuster = KatanaAdapter(), GobusterAdapter()
    for asset in list(url_pool.values()):
        for u in katana.crawl(asset, config, limiter):
            url_pool.setdefault(u, Asset(url=u, host=urlparse(u).hostname or ""))
        for path, code in gobuster.dir_scan(asset, config, limiter):
            u = asset.url.rstrip("/") + path
            url_pool.setdefault(u, Asset(url=u, host=asset.host, status_code=code))

    # 4. 敏感路径探测（任务书 1.2）：GET、限流、禁重定向、状态码 200 且非空才入池
    for a in req.assets:
        base = a.url.rstrip("/")
        host = urlparse(base).netloc
        for path in SENSITIVE_PATHS:
            limiter.wait(host=host)
            u = base + path
            if u in url_pool:
                existing = url_pool[u]
                if "sensitive_file" not in (existing.fingerprint or {}):
                    existing.fingerprint = {**(existing.fingerprint or {}),
                                            "sensitive_file": path}
                if not existing.title:
                    existing.title = f"敏感文件: {path}"
                continue
            try:
                r = httpx.get(u, timeout=config.timeout_sec,
                              follow_redirects=False)
            except Exception:
                continue
            if r.status_code == 200 and len(r.content) >= 8:
                url_pool[u] = Asset(url=u, host=a.host, status_code=200,
                                    fingerprint={"sensitive_file": path},
                                    title=f"敏感文件: {path}")

    # 5. page_hash + status_code + title 填充（同一次请求拿全三个字段）
    for u, asset in url_pool.items():
        if asset.page_hash:
            continue
        h, code, title = _probe(u)
        if h:
            asset.page_hash = h
        if asset.status_code is None:
            asset.status_code = code
        if asset.title is None:
            asset.title = title

    assets = sorted(url_pool.values(), key=lambda a: a.url)
    _fill_fingerprints(assets, config)      # ← 必须在 return 之前（原来是死代码）

    return DiscoveryResponse(assets=assets)