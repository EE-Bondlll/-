"""编排执行器：按巡检计划逐步执行，聚合 → 去重 → 定级 → 基线 → 告警。

对应任务书 4.3/4.4：白名单校验、QPS 限速、统一结果聚合、signature 去重、风险定级。
"""
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from . import clients
from . import reviewer as reviewer_mod

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
    def __init__(self, detector: clients.DetectorClient, data: clients.DataClient,
                 reviewer=None):
        self.detector = detector
        self.data = data
        self.reviewer = reviewer or reviewer_mod.create_reviewer()
        self.limiter = RateLimiter(qps=5)

    def run(self, plan: dict, config_id: str) -> dict:
        """执行计划，返回聚合后的巡检结果。

        plan 可携带 targets（受影响资产列表）→ 复测模式：跳过全站发现，
        仅对指定资产执行检测；否则为全量模式：先做资产发现。
        """
        domains = plan.get("domains", [])
        cfg = {"rate_limit_qps": 20, "non_destructive": True, "timeout_sec": 30}
        all_risks: list[dict] = []
        assets: list[dict] = []

        targets = plan.get("targets")
        if targets:
            # 复测模式（4.6）：只重扫受影响资产，不再爬全站
            assets = targets
            scan_mode = "retest"
        else:
            # 阶段1：资产发现（discovery）——契约：Asset 需 url（含 scheme）+ host
            entries = []
            for d in domains:
                u = d if d.startswith(("http://", "https://")) else "http://" + d
                entries.append({"url": u, "host": u.split("//")[-1].split("/")[0]})
            disc = self.detector.scan("/scan/discovery", entries, cfg)
            assets = check_whitelist(disc.get("assets", []), domains)
            scan_mode = "full"
        self.data.write_assets(assets)

        # 阶段2-5：并行检测（vuln / tamper / malware / sensitive 并发，互不依赖）
        detect_plan = [s for s in plan["steps"]
                       if s["stage"] == "detect" and s["service"] != "agent-core"]

        def _run_detect(step: dict) -> dict:
            self.limiter.acquire()
            if step["service"] == "detectors":
                return self.detector.scan(step["endpoint"], assets, cfg)
            if step["service"] == "sensitive-report":
                # 敏感信息检测：MOCK=0 调成员C 的 /scan/sensitive，否则内置示例
                return self.data.scan_sensitive(step, assets, cfg)
            return {}

        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="detect") as ex:
            futures = {ex.submit(_run_detect, s): s for s in detect_plan}
            for fut in as_completed(futures):
                resp = fut.result()  # 任一检测失败不阻断其他，异常由外层任务捕获
                all_risks.extend(resp.get("risks", []))

        # 阶段6：去重（signature 唯一）
        dedup = self._dedup(all_risks)

        # 阶段7（4.5）：AI 误报研判 + 三段式解释，写回 status / ai_explanation
        dedup = self.reviewer.review(dedup)
        self.data.write_risks(dedup)

        # 阶段8-9：基线对比 + 告警（只统计研判确认为真实风险的高危）
        baseline = self.data.baseline_diff(scope=",".join(domains))
        high_count = sum(1 for r in dedup
                         if r["status"] == "confirmed"
                         and r["severity"] in ("critical", "high"))
        if high_count > 0:
            self.data.send_alert(
                "high" if high_count >= 3 else "medium",
                f"巡检完成：确认 {high_count} 个高危风险（mock 环境）",
                {"plan_id": plan["plan_id"], "config_id": config_id},
            )

        return {
            "config_id": config_id,
            "plan_id": plan["plan_id"],
            "scan_mode": scan_mode,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "assets_found": len(assets),
            "risks_raw": len(all_risks),
            "risks_after_dedup": len(dedup),
            "review_mode": getattr(self.reviewer, "mode", "rule"),
            "confirmed_high": high_count,
            "baseline": baseline,
            "risks": dedup,
        }

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
