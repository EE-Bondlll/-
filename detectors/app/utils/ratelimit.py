import time, threading

class QPSLimiter:
    """全局 + 每 host 两级令牌桶，强制 QPS ≤ 5"""
    def __init__(self, qps: int = 5):
        self.interval = 1.0 / qps
        self._lock = threading.Lock()
        self._next_global = 0.0
        self._next_host: dict[str, float] = {}

    def wait(self, host: str):
        with self._lock:
            now = time.monotonic()
            t = max(now, self._next_global, self._next_host.get(host, 0.0))
            self._next_global = t + self.interval
            self._next_host[host] = t + self.interval
            delay = t - now
        if delay > 0:
            time.sleep(delay)

limiter = QPSLimiter(qps=5)