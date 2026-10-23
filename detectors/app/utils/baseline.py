"""篡改检测的页面基线存储（JSON 文件，原子写入，线程安全）。"""
import json
import os
import threading
from datetime import datetime, timezone

DEFAULT_PATH = os.path.expanduser("~/.secbot/baselines.json")


class BaselineStore:
    def __init__(self, path: str = DEFAULT_PATH):
        self.path = path
        self._lock = threading.Lock()
        self._data = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.path):
            try:
                with open(self.path, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)  # 原子替换，防中途写坏

    def get(self, url: str) -> dict | None:
        return self._data.get(url)

    def put(self, url: str, record: dict) -> None:
        with self._lock:
            rec = dict(record)
            rec["baseline_at"] = datetime.now(timezone.utc).isoformat()
            self._data[url] = rec
            self._save()

    def remove(self, url: str) -> None:
        with self._lock:
            if url in self._data:
                del self._data[url]
                self._save()
