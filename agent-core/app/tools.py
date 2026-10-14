"""工具调用容错（任务书 4.2 第 4 项）：超时、重试、失败标记、跳过继续。

编排器（4.3）对下游检测器/数据服务的每次调用都经 call_with_retry 包装，
保证单步失败不中断整轮巡检。
"""
import time


def call_with_retry(fn, *, timeout_sec: float = 30.0, retries: int = 2,
                    label: str = "tool", skip_on_fail: bool = True) -> dict:
    """执行 fn() 并返回统一结果。

    - 超时/异常：按 retries 重试（指数退避）
    - 仍失败：返回 {"ok": False, "failed": True, "skipped": skip_on_fail, "error": ...}
      不抛出异常，调用方根据 skipped 决定跳过还是终止。
    """
    last_err: Exception | None = None
    for attempt in range(retries + 1):
        try:
            result = fn(timeout=timeout_sec)
            return {"ok": True, "result": result, "label": label, "attempts": attempt + 1}
        except Exception as e:  # 含超时
            last_err = e
            if attempt < retries:
                time.sleep(1.0 * (attempt + 1))  # 退避
    return {
        "ok": False, "failed": True, "label": label,
        "skipped": skip_on_fail, "error": str(last_err),
        "attempts": retries + 1,
    }
