"""敏感信息定义管理（任务书 4.1）。

规则类型：keyword（关键词）/ regex（正则）/ file_type（文件类型）/ sample（样例文件）。
存储：FileStore（JSON 文件），结构对齐 contracts/schema.sql 的 sensitive_rules 表，
成员C 数据服务就绪后可无缝迁移。
"""
import hashlib
import os
import uuid

from . import storage

RULES_FILE = os.path.join(storage.DATA_DIR, "sensitive_rules.json")
SAMPLES_DIR = os.path.join(storage.DATA_DIR, "samples")

RULE_TYPES = {"keyword", "regex", "file_type", "sample"}


class RuleStore:
    def __init__(self, path: str = RULES_FILE):
        self._store = storage.FileStore(path)

    def add(self, rule: dict) -> dict:
        rule_id = uuid.uuid4().hex[:12]
        rule = {"rule_id": rule_id, "enabled": True, **rule}
        self._store.save(rule_id, rule)
        return rule

    def list_rules(self, rule_type: str | None = None, enabled: bool | None = None) -> list[dict]:
        rules = self._store.list_all()
        if rule_type:
            rules = [r for r in rules if r.get("rule_type") == rule_type]
        if enabled is not None:
            rules = [r for r in rules if r.get("enabled") is enabled]
        return rules

    def update(self, rule_id: str, patch: dict) -> dict | None:
        rule = self._store.get(rule_id)
        if rule is None:
            return None
        rule.update(patch)
        self._store.save(rule_id, rule)
        return rule

    def delete(self, rule_id: str) -> bool:
        rule = self._store.get(rule_id)
        if rule is None:
            return False
        rule["enabled"] = False  # 软删除，保留审计痕迹
        self._store.save(rule_id, rule)
        return True


def save_sample(file_bytes: bytes, filename: str) -> dict:
    """样例文件入库：返回 file_id 与 sha256，供后续相似度比对使用。"""
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    file_id = uuid.uuid4().hex[:12]
    sha = hashlib.sha256(file_bytes).hexdigest()
    safe_name = os.path.basename(filename)  # 防路径穿越
    path = os.path.join(SAMPLES_DIR, f"{file_id}_{safe_name}")
    with open(path, "wb") as f:
        f.write(file_bytes)
    return {"file_id": file_id, "filename": safe_name, "sha256": sha,
            "size": len(file_bytes), "path": path}
