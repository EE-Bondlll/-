"""存储层：配置与任务的持久化抽象。

当前实现：FileStore（JSON 文件，零依赖，开发阶段使用）。
后续切换：成员C 的 PostgreSQL 就绪后，新增 PGStore 实现同一接口即可，
main.py 无需改动（通过工厂函数选择后端）。
"""
import hashlib
import json
import os
import threading

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
CONFIGS_FILE = os.path.join(DATA_DIR, "configs.json")
JOBS_FILE = os.path.join(DATA_DIR, "jobs.json")
AUDIT_FILE = os.path.join(DATA_DIR, "audit_logs.json")


def _ensure_dir(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)


class FileStore:
    """基于单个 JSON 文件的线程安全 KV 存储。"""

    def __init__(self, path: str):
        self._path = path
        self._lock = threading.Lock()
        _ensure_dir(path)
        if not os.path.exists(path):
            self._write({})

    def _read(self) -> dict:
        with open(self._path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _write(self, data: dict):
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self._path)  # 原子替换，避免半写状态

    def save(self, key: str, value: dict):
        with self._lock:
            data = self._read()
            data[key] = value
            self._write(data)

    def get(self, key: str) -> dict | None:
        with self._lock:
            return self._read().get(key)

    def list_all(self) -> list[dict]:
        with self._lock:
            return list(self._read().values())


def make_config_id(domains: list[str]) -> str:
    """配置 ID：由授权域名集合确定性生成（同域名集合→同 ID，幂等保存）。"""
    return hashlib.sha256(",".join(sorted(domains)).encode()).hexdigest()[:12]
