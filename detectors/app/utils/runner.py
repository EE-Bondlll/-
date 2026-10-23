import subprocess
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=4), reraise=False)
def run_cmd(cmd: list[str], timeout_sec: int = 30) -> tuple[int, str, str]:
    """返回 (returncode, stdout, stderr)；超时按重试处理，最终失败返回非零码由上层标记 skip。"""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"