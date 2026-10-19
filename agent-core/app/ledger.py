"""风险账本：基线对比 + 复测队列 + 告警触发（任务书 4.6）。

A 侧本地闭环实现（不依赖成员C 数据服务即可演示与验收）：
- 基线对比：本次全量结果 vs 上次全量快照 → 新增 / 已修复 / 持续风险三类清单
- 复测队列：仅重扫受影响资产（active 风险所属资产），未再命中自动消警（status=fixed）
- 告警触发：按级别阈值（critical/high），同一 signature 24h 内去重，事件留痕
  （成员C 告警通道就绪后，将 channel 从 mock 切换为 feishu/smtp/webhook 即可）

数据文件（agent-core/data/，已 gitignore）：
- ledger.json    : config:signature → 风险状态（active/fixed + first_seen/last_seen/fixed_at）
- snapshots.json : config_id → 最近一次全量快照的 signature 集（用于 diff）
- baselines.json : config_id → 最近一次基线对比结果（新增/已修复/持续）
- alerts.json    : 告警事件（signature 维度，24h 去重窗口）
"""
import os
import uuid
from datetime import datetime, timedelta, timezone

from . import storage

LEDGER_FILE = os.path.join(storage.DATA_DIR, "ledger.json")
SNAPSHOT_FILE = os.path.join(storage.DATA_DIR, "snapshots.json")
BASELINE_FILE = os.path.join(storage.DATA_DIR, "baselines.json")
ALERTS_FILE = os.path.join(storage.DATA_DIR, "alerts.json")

ALERT_WINDOW_HOURS = 24
DEFAULT_ALERT_THRESHOLD = "high"

_SEVERITY_LEVELS = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Ledger:
    def __init__(self):
        self._ledger = storage.FileStore(LEDGER_FILE)
        self._snapshots = storage.FileStore(SNAPSHOT_FILE)
        self._baselines = storage.FileStore(BASELINE_FILE)
        self._alerts = storage.FileStore(ALERTS_FILE)

    # ---------- 基础读写 ----------

    @staticmethod
    def _key(config_id: str, signature: str) -> str:
        return f"{config_id}:{signature}"

    def _get_entry(self, config_id: str, signature: str) -> dict | None:
        return self._ledger.get(self._key(config_id, signature))

    def _entry_view(self, config_id: str, signature: str) -> dict:
        entry = self._get_entry(config_id, signature) or {"signature": signature}
        return {k: entry.get(k) for k in (
            "signature", "asset_url", "category", "severity", "title",
            "status", "first_seen", "last_seen", "fixed_at",
        )}

    # ---------- 全量巡检后入账（基线对比） ----------

    def apply_full(self, config_id: str, risks: list[dict], job_id: str) -> dict:
        """全量巡检结果入账：与上次全量快照对比输出三类清单，更新状态与快照。"""
        prev = self._snapshots.get(config_id) or {}
        cur = {r["signature"]: r for r in risks if r.get("signature")}

        new_sigs = [s for s in cur if s not in prev]
        fixed_sigs = [s for s in prev if s not in cur]
        persistent_sigs = [s for s in prev if s in cur]

        now = _now_iso()
        for sig, r in cur.items():
            entry = self._get_entry(config_id, sig)
            if entry is None:
                entry = {"config_id": config_id, "signature": sig, "status": "active",
                         "first_seen": now, "last_seen": now}
            else:
                entry["status"] = "active"
                entry["last_seen"] = now
            entry.update({k: r.get(k) for k in (
                "asset_url", "category", "severity", "title", "tool", "template")})
            self._ledger.save(self._key(config_id, sig), entry)

        for sig in fixed_sigs:
            entry = self._get_entry(config_id, sig)
            if entry and entry.get("status") != "fixed":
                entry["status"] = "fixed"
                entry["fixed_at"] = now
                self._ledger.save(self._key(config_id, sig), entry)

        # 保存本次快照（供下次 diff）
        self._snapshots.save(config_id, {
            s: {"category": r.get("category"), "severity": r.get("severity"),
                "title": r.get("title")}
            for s, r in cur.items()
        })

        diff = {
            "scan_mode": "full",
            "job_id": job_id,
            "computed_at": now,
            "new": [self._entry_view(config_id, s) for s in new_sigs],
            "fixed": [self._entry_view(config_id, s) for s in fixed_sigs],
            "persistent": [self._entry_view(config_id, s) for s in persistent_sigs],
        }
        self._baselines.save(config_id, diff)
        return diff

    def last_baseline(self, config_id: str) -> dict | None:
        """最近一次全量基线对比结果。"""
        return self._baselines.get(config_id)

    # ---------- 复测队列 ----------

    def retest_targets(self, config_id: str) -> list[dict]:
        """受影响资产：该 config 下 status=active 的风险所属资产（去重）。"""
        seen: dict[str, str] = {}
        for entry in self._ledger.list_all():
            if (entry.get("config_id") == config_id
                    and entry.get("status") == "active"
                    and entry.get("asset_url")):
                seen[entry["asset_url"]] = entry["asset_url"]
        return [{"url": u} for u in sorted(seen)]

    def apply_retest(self, config_id: str, targets: list[dict],
                     risks: list[dict], job_id: str) -> dict:
        """复测结果入账：仅判定受影响资产范围内的 active 风险；未再命中自动消警。"""
        now = _now_iso()
        target_urls = {a["url"] for a in targets or []}
        cur_sigs = {r["signature"]: r for r in risks if r.get("signature")}

        affected = [
            e for e in self._ledger.list_all()
            if e.get("config_id") == config_id and e.get("status") == "active"
            and e.get("asset_url") in target_urls
        ]

        still_active, cleared = [], []
        for entry in affected:
            sig = entry["signature"]
            if sig in cur_sigs:
                entry["status"] = "active"
                entry["last_seen"] = now
                self._ledger.save(self._key(config_id, sig), entry)
                still_active.append(self._entry_view(config_id, sig))
            else:
                entry["status"] = "fixed"
                entry["fixed_at"] = now
                self._ledger.save(self._key(config_id, sig), entry)
                cleared.append(self._entry_view(config_id, sig))

        # 复测中新发现（账本中不存在）→ 直接入账 active
        newly_found = []
        for sig, r in cur_sigs.items():
            if self._get_entry(config_id, sig) is None:
                entry = {"config_id": config_id, "signature": sig, "status": "active",
                         "first_seen": now, "last_seen": now,
                         "asset_url": r.get("asset_url"), "category": r.get("category"),
                         "severity": r.get("severity"), "title": r.get("title"),
                         "tool": r.get("tool"), "template": r.get("template")}
                self._ledger.save(self._key(config_id, sig), entry)
                newly_found.append(self._entry_view(config_id, sig))

        return {
            "scan_mode": "retest",
            "job_id": job_id,
            "computed_at": now,
            "cleared": cleared,          # 自动消警（置 fixed）
            "still_active": still_active,
            "newly_found": newly_found,
        }

    # ---------- 告警触发 ----------

    def _alert_recent(self, config_id: str, signature: str) -> bool:
        window_start = (datetime.now(timezone.utc)
                        - timedelta(hours=ALERT_WINDOW_HOURS)).isoformat()
        for a in self._alerts.list_all():
            if (a.get("config_id") == config_id
                    and a.get("signature") == signature
                    and a.get("created_at", "") >= window_start):
                return True
        return False

    def evaluate_alerts(self, config_id: str, risks: list[dict],
                        threshold: str = DEFAULT_ALERT_THRESHOLD) -> list[dict]:
        """按级别阈值触发告警：仅 confirmed 且 severity >= threshold；同一 signature 24h 去重。"""
        min_level = _SEVERITY_LEVELS.get(threshold, 3)
        now = datetime.now(timezone.utc)
        triggered = []
        for r in risks:
            if r.get("status") != "confirmed":
                continue
            if _SEVERITY_LEVELS.get(r.get("severity", "low"), 0) < min_level:
                continue
            sig = r.get("signature")
            if not sig:
                continue
            if self._alert_recent(config_id, sig):
                continue
            alert = {
                "alert_id": uuid.uuid4().hex[:12],
                "config_id": config_id,
                "signature": sig,
                "level": r.get("severity"),
                "category": r.get("category"),
                "title": r.get("title"),
                "asset_url": r.get("asset_url"),
                "message": f"[{r.get('severity')}] {r.get('title')} @ {r.get('asset_url')}",
                "channel": "mock",   # 成员C 通道就绪后：feishu / smtp / webhook
                "created_at": now.isoformat(),
            }
            self._alerts.save(alert["alert_id"], alert)
            triggered.append(alert)
        return triggered

    def list_alerts(self, limit: int = 50) -> list[dict]:
        entries = self._alerts.list_all()
        entries.sort(key=lambda e: e.get("created_at", ""), reverse=True)
        return entries[:limit]
