import os
import shutil

# 系统工具目录，按优先级查找（避开 .venv 里的同名 Python 脚本）
TOOL_DIRS = ["/usr/local/bin", "/usr/bin", os.path.expanduser("~/.local/bin")]


def resolve_tool(name: str):
    for d in TOOL_DIRS:
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return shutil.which(name)  # 兜底：按 PATH 找
