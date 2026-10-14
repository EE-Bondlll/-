"""编排执行器：按巡检计划逐步执行，聚合 → 去重 → 定级 → 基线 → 告警。

对应任务书 4.3/4.4：白名单校验、QPS 限速、统一结果聚合、signature 去重、风险定级。
"""
import time
from datetime import datetime, timezone

from . import clients

# 简单 QPS 限速（令牌桶）：全局 + 每资产
class RateLimiter:
    def __init__(self, qps: float = 5.0):
        self.qps = qps
        self._last = time.monotonic()
        self._tokens = qps

    def acquire(self):
        now = time.monotonic()
        self._tokens = min(self.qps, self._tokens + (now - self._last) * self.qps)
        self._last = now
        if self._tokens < 1:
            time.sleep((1 - self._tokens) / self.qps)
            self._tokens = 0
        else:
            self._tokens -= 1


def _host_of(url: str) -> str:
    return (url.split("//")[-1].split("/")[0]).lower()


def check_whitelist(assets: list[dict], domains: list[str]) -> list[dict]:
    """授权白名单校验：资产 host 必须属于配置的授权域名（含子域）。"""
    allowed = {d.lower().lstrip("*.") for d in domains}
    passed = []
    for a in assets:
        host = _host_of(a["url"])
        if any(host == d or host.endswith("." + d) for d in allowed):
            passed.append(a)
    return passed


class Orchestrator:
    def __init__(self, detector: clients.DetectorClient, data: clients.DataClient):
        self.detector = detector
        self.data = data
        self.limiter = RateLimiter(qps=5)

    def run(self, plan: dict, config_id: str) -> dict:
        """执行计划，返回聚合后的巡检结果。"""
        domains = plan.get("domains", [])
        cfg = {"rate_limit_qps": 5, "non_destructive": True, "timeout_sec": 30}
        all_risks: list[dict] = []
        assets: list[dict] = []

        # 阶段1：资产发现（discovery）
        disc = self.detector.scan("/scan/discovery",
                                  [{"url": d} for d in domains], cfg)
        assets = check_whitelist(disc.get("assets", []), domains)
        self.data.write_assets(assets)

        # 阶段2-5：并行检测（vuln / tamper / malware / sensitive）
        detect_plan = [s for s in plan["steps"]
                       if s["stage"] == "detect" and s["service"] != "agent-core"]
        for step in detect_plan:
            self.limiter.acquire()
            resp = self.detector.scan(step["endpoint"], assets, cfg) \
                if step["service"] == "detectors" else \
                self._sensitive_scan(step["endpoint"], assets, cfg)
            all_risks.extend(resp.get("risks", []))

        # 阶段6：去重（signature 唯一）+ 定级
        dedup = self._dedup(all_risks)
        self.data.write_risks(dedup)

        # 阶段7-8：基线对比 + 告警（统计高危）
        baseline = self.data.baseline_diff(scope=",".join(domains))
        high_count = sum(1 for r in dedup if r["severity"] in ("critical", "high"))
        if high_count > 0:
            self.data.send_alert(
                "high" if high_count >= 3 else "medium",
                f"巡检完成：发现 {high_count} 个高危风险（mock 环境）",
                {"plan_id": plan["plan_id"], "config_id": config_id},
            )

        return {
            "config_id": config_id,
            "plan_id": plan["plan_id"],
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "assets_found": len(assets),
            "risks_raw": len(all_risks),
            "risks_after_dedup": len(dedup),
            "high_count": high_count,
            "baseline": baseline,
            "risks": dedup,
        }

    def _sensitive_scan(self, endpoint, assets, cfg):
        # 敏感信息检测：成员C 的引擎；mock 时由 DetectorClient 统一模拟（此处返回 leak 示例）
        return {"risks": [{
            "asset_url": a["url"], "category": "leak", "severity": "high",
            "title": "备份文件暴露环境变量（含数据库口令）（mock）",
            "description": "[mock] 命中文件类型规则 .bak 与正则 DB_PASSWORD",
            "evidence": {"matched_context": "DB_PASSWORD=****（已脱敏，mock）"},
            "raw_output": "{}", "tool": "sensitive-engine", "template": "file_type:.bak",
            "first_seen": "2026-10-14T00:00:00+08:00", "last_seen": "2026-10-14T00:00:00+08:00",
            "status": "active",
            "signature": clients._signature(a["url"], "leak", "备份文件暴露环境变量（含数据库口令）（mock）"),
        } for a in assets[:1]]}

    @staticmethod
    def _dedup(risks: list[dict]) -> list[dict]:
        """按 signature 去重：同源发现只保留一条（跨工具、跨轮次）。"""
        seen: dict[str, dict] = {}
        for r in risks:
            sig = r.get("signature")
            if sig and sig in seen:
                continue  # 保留首次出现
            seen[sig] = r
        return list(seen.values())
