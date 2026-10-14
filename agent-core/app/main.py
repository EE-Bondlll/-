"""Agent Core - 智能巡检编排服务（最小骨架 v0.1）

职责：配置管理、任务规划、编排调度、结果研判、风险闭环、恒脑集成。
当前版本：仅提供 /health 与 /api/config 两个接口（内存存储），
下一步将配置持久化切换到 PostgreSQL（成员C 建表后）。

运行：uvicorn app.main:app --reload --port 8000
"""
from fastapi import FastAPI
from pydantic import BaseModel
import hashlib

app = FastAPI(title="Agent Core - 智能巡检编排服务", version="0.1.0")


class Config(BaseModel):
    """巡检授权配置：授权域名、巡检范围、周期、敏感信息定义。"""
    domains: list[str]              # 授权域名（白名单，任何目标必须先匹配）
    scope: str = "full"             # 巡检范围：full / subdomains / paths
    cron: str = "0 2 * * *"         # 巡检周期（cron 表达式）
    sensitive_rules: list[str] = [] # 敏感信息定义（关键词/正则/文件类型，暂存）


# 第一步先用内存字典占位，第二步接 PostgreSQL
configs: dict[str, dict] = {}


@app.get("/health")
def health():
    """健康检查：供 docker-compose 与成员B/C 联调探测。"""
    return {"status": "ok", "service": "agent-core", "version": app.version}


@app.post("/api/config")
def save_config(cfg: Config):
    """录入巡检授权配置，返回 config_id。"""
    key = hashlib.sha256(",".join(cfg.domains).encode()).hexdigest()[:12]
    configs[key] = cfg.model_dump()
    return {"config_id": key, "saved": True, "domains": cfg.domains}


@app.get("/api/config/{config_id}")
def get_config(config_id: str):
    """查询已保存的巡检配置。"""
    cfg = configs.get(config_id)
    return cfg if cfg else {"error": "config not found"}
