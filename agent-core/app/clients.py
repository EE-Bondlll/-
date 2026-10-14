"""下游服务客户端（按 contracts/api_contracts.md 调用成员B/C 服务）。

并行开发策略（任务书铁律）：默认 MOCK_MODE=1 —— 不请求真实服务，
返回符合契约的 mock 结果，让成员A 的编排在 B/C 未就绪时即可独立开发。
B/C 就绪后设 MOCK_MODE=0 并配置 base_url 即切换真实服务，编排代码零改动。
"""
import hashlib
import os
import uuid

MOCK = os.getenv("MOCK_MODE", "1") == "1"
DETECTOR_BASE = os.getenv("DETECTOR_BASE_URL", "http://detectors:8001")
DATA_BASE = os.getenv("DATA_BASE_URL", "http://sensitive-report:8002")


def _signature(url: str, category: str, title: str, detail: str = "") -> str:
    """统一去重键：sha256(url + category + title + detail)。"""
    return hashlib.sha256(f"{url}|{category}|{title}|{detail}".encode()).hexdigest()


def _risk(url, category, severity, title, tool, template, detail=""):
    return {
        "asset_url": url,
        "category": category,
        "severity": severity,
        "title": title,
        "description": f"[mock] {title}",
        "evidence": {"request_sample": "MOCK / HTTP/1.1", "response_sample": "MOCK 200 OK"},
        "raw_output": "{}",
        "tool": tool,
        "template": template,
        "first_seen": "2026-10-14T00:00:00+08:00",
        "last_seen": "2026-10-14T00:00:00+08:00",
        "status": "active",
        "signature": _signature(url, category, title, detail),
    }


class DetectorClient:
    """成员B 检测器服务客户端（discovery / vuln / tamper / malware）。"""

    def scan(self, endpoint: str, assets: list[dict], config: dict | None = None) -> dict:
        """按契约调用检测器。endpoint ∈ /scan/discovery|/scan/vuln|/scan/tamper|/scan/malware。"""
        if MOCK:
            return self._mock(endpoint, assets)
        import httpx
        resp = httpx.post(
            DETECTOR_BASE + endpoint,
            json={"assets": assets, "config": config or {}},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def _mock(self, endpoint: str, assets: list[dict]) -> dict:
        if endpoint == "/scan/discovery":
            # 模拟：每个主域产出 2 个页面资产（首页 + 登录页），带指纹
            out_assets = []
            for a in assets:
                url = a["url"].rstrip("/")
                fp = {"cms": "wordpress", "version": "6.0", "server": "nginx/1.18"}
                out_assets.append({
                    "url": url + "/", "host": url.split("//")[-1],
                    "fingerprint": fp, "status_code": 200,
                    "page_hash": hashlib.sha256((url + "|home").encode()).hexdigest(),
                    "title": "首页（mock）",
                })
                out_assets.append({
                    "url": url + "/wp-login.php", "host": url.split("//")[-1],
                    "fingerprint": fp, "status_code": 200,
                    "page_hash": hashlib.sha256((url + "|login").encode()).hexdigest(),
                    "title": "登录页（mock）",
                })
            return {"job_id": uuid.uuid4().hex[:12], "assets": out_assets}

        risks = []
        for a in assets:
            url = a["url"]
            if endpoint == "/scan/vuln":
                risks.append(_risk(url, "vuln", "medium",
                                   "Nuclei 模板命中示例：CVE-2026-0001（mock）",
                                   "nuclei", "cve.yaml", url))
                risks.append(_risk(url, "weak_config", "low",
                                   "缺少 X-Frame-Options 安全头（mock）",
                                   "headers-check", "security_headers", url))
            elif endpoint == "/scan/tamper":
                risks.append(_risk(url, "tamper", "high",
                                   "页面内容哈希与基线不一致，疑似被篡改（mock）",
                                   "tamper-engine", "hash_baseline", url))
            elif endpoint == "/scan/malware":
                risks.append(_risk(url, "bad_link", "medium",
                                   "页面含可疑外链（mock）",
                                   "malware-engine", "bad_link_list", url))
        return {"job_id": uuid.uuid4().hex[:12], "risks": risks}


class DataClient:
    """成员C 数据 / 告警 / 报告服务客户端。"""

    def write_assets(self, assets: list[dict]):
        if MOCK:
            return {"written": len(assets)}
        import httpx
        return httpx.post(DATA_BASE + "/data/assets/batch", json={"assets": assets}, timeout=30).json()

    def write_risks(self, risks: list[dict]):
        if MOCK:
            return {"written": len(risks)}
        import httpx
        return httpx.post(DATA_BASE + "/data/risks/batch", json={"risks": risks}, timeout=30).json()

    def baseline_diff(self, scope: str | None = None):
        if MOCK:
            return {"new": [], "fixed": [], "persistent": []}
        import httpx
        return httpx.get(DATA_BASE + "/data/baseline-diff", params={"scope": scope}, timeout=30).json()

    def send_alert(self, level: str, message: str, payload: dict | None = None):
        if MOCK:
            return {"sent": True, "channel": "mock", "level": level}
        import httpx
        return httpx.post(DATA_BASE + "/alert/send",
                          json={"level": level, "message": message, "payload": payload or {}},
                          timeout=30).json()
