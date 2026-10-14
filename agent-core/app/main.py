"""Agent Core - 智能巡检编排服务（v0.3）

已实现（任务书 4.1 / 4.2）：
- 配置管理：POST/GET /api/config（JSON 文件持久化 + 校验，PG 后端预留）
- 敏感信息定义管理：/api/rules（关键词/正则/文件类型 CRUD）+ 样例文件上传
- 巡检计划：POST /api/plan（规则版 / LLM 版，LLM 失败自动降级）
- 指纹 → 检测策略路由：POST /api/strategy
- LLM 状态：GET /api/llm/status
- 任务入口：POST /api/jobs/start、GET /api/jobs（4.3 编排的前置）

运行：uvicorn app.main:app --reload --port 8000
"""
import re
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel, Field

from . import planner, rules, storage

app = FastAPI(title="Agent Core - 智能巡检编排服务", version="0.3.0")

# 存储后端（当前 JSON 文件；PG 就绪后换成 PGStore 实现同接口即可）
config_store = storage.FileStore(storage.CONFIGS_FILE)
job_store = storage.FileStore(storage.JOBS_FILE)
rule_store = rules.RuleStore()

# ---------- 校验 ----------

_DOMAIN_RE = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_VALID_SCOPES = {"full", "subdomains", "paths"}


def validate_domains(domains: list[str]):
    bad = [d for d in domains if not _DOMAIN_RE.match(d)]
    if bad:
        raise HTTPException(status_code=422, detail=f"域名格式非法: {bad}")


def validate_config(cfg: dict):
    if not cfg.get("domains"):
        raise HTTPException(status_code=422, detail="domains 不能为空")
    validate_domains(cfg["domains"])
    if cfg.get("scope") not in _VALID_SCOPES:
        raise HTTPException(status_code=422,
                            detail=f"scope 必须为 {sorted(_VALID_SCOPES)} 之一")
    cron = cfg.get("cron", "")
    # 宽松校验：5 段 cron（分 时 日 月 周）
    if not re.match(r"^(\S+\s+){4}\S+$", cron):
        raise HTTPException(status_code=422, detail=f"cron 表达式格式非法: {cron}")


# ---------- 模型 ----------

class Config(BaseModel):
    """巡检授权配置。"""
    domains: list[str] = Field(min_length=1, description="授权域名（白名单）")
    scope: str = "full"
    cron: str = "0 2 * * *"
    sensitive_rules: list[str] = []


class PlanRequest(BaseModel):
    config_id: str


class JobStartRequest(BaseModel):
    config_id: str


class RuleIn(BaseModel):
    rule_type: str = Field(description="keyword | regex | file_type | sample")
    name: str
    pattern: str = ""
    severity: str = "medium"
    enabled: bool = True


class RulePatch(BaseModel):
    pattern: str | None = None
    severity: str | None = None
    enabled: bool | None = None


# ---------- 健康检查 ----------

@app.get("/health")
def health():
    return {"status": "ok", "service": "agent-core", "version": app.version}


# ---------- 4.1 配置管理 ----------

@app.post("/api/config")
def save_config(cfg: Config):
    """录入巡检授权配置（幂等：同域名集合覆盖保存）。"""
    data = cfg.model_dump()
    validate_config(data)
    config_id = storage.make_config_id(data["domains"])
    config_store.save(config_id, data)
    return {"config_id": config_id, "saved": True, "domains": data["domains"]}


@app.get("/api/config/{config_id}")
def get_config(config_id: str):
    cfg = config_store.get(config_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail="config not found")
    return cfg


# ---------- 4.1 敏感信息定义管理 ----------

@app.post("/api/rules")
def add_rule(rule: RuleIn):
    if rule.rule_type not in rules.RULE_TYPES:
        raise HTTPException(status_code=422, detail=f"rule_type 必须为 {sorted(rules.RULE_TYPES)} 之一")
    if rule.rule_type != "sample" and not rule.pattern:
        raise HTTPException(status_code=422, detail="keyword/regex/file_type 规则必须提供 pattern")
    saved = rule_store.add(rule.model_dump())
    return {"rule_id": saved["rule_id"], "saved": True}


@app.get("/api/rules")
def list_rules(rule_type: str | None = None, enabled: bool | None = None):
    if rule_type and rule_type not in rules.RULE_TYPES:
        raise HTTPException(status_code=422, detail=f"rule_type 必须为 {sorted(rules.RULE_TYPES)} 之一")
    return {"rules": rule_store.list_rules(rule_type, enabled)}


@app.patch("/api/rules/{rule_id}")
def update_rule(rule_id: str, patch: RulePatch):
    updated = rule_store.update(rule_id, patch.model_dump(exclude_none=True))
    if updated is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return updated


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: str):
    if not rule_store.delete(rule_id):
        raise HTTPException(status_code=404, detail="rule not found")
    return {"rule_id": rule_id, "deleted": True, "note": "软删除（enabled=false）"}


@app.post("/api/rules/sample")
async def upload_sample(file: UploadFile = File(...)):
    """上传敏感信息样例文件（如 .env 样例），存本地并返回指纹供比对。"""
    if file.filename is None or file.filename == "":
        raise HTTPException(status_code=422, detail="文件名不能为空")
    meta = rules.save_sample(await file.read(), file.filename)
    return {"saved": True, **meta}


# ---------- 4.2 巡检计划与策略路由 ----------

@app.post("/api/plan")
def make_plan(req: PlanRequest):
    """读取配置 → 生成巡检计划（LLM 版优先，失败/未配置时规则版）。"""
    cfg = config_store.get(req.config_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail="config not found")
    return planner.create_planner().build_plan(cfg)


@app.post("/api/strategy")
def strategy_for(fp: dict):
    """指纹 → 检测策略路由（供自测与演示）。"""
    return {"fingerprint": fp, "steps": planner.route_strategy(fp)}


@app.get("/api/llm/status")
def llm_status():
    p = planner.LLMPlanner()
    return {
        "mode": "llm" if p.available() else "rule",
        "llm_configured": p.available(),
        "base_url": p.base_url,
        "model": p.model,
        "note": "设置环境变量 LLM_API_KEY 后启用 LLM 规划（恒脑/DeepSeek OpenAI 兼容接口）",
    }


# ---------- 任务入口（4.3 前置） ----------

@app.post("/api/jobs/start")
def start_job(req: JobStartRequest):
    """发起一次巡检：生成计划、记录任务、返回 job_id（执行由 4.3 编排器接管）。"""
    cfg = config_store.get(req.config_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail="config not found")
    plan = planner.create_planner().build_plan(cfg)
    job = {
        "job_id": uuid.uuid4().hex[:12],
        "job_type": "manual",
        "config_id": req.config_id,
        "plan_id": plan["plan_id"],
        "status": "pending",               # pending → running → done/failed
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "plan": plan,
    }
    job_store.save(job["job_id"], job)
    return {"job_id": job["job_id"], "status": job["status"], "plan": plan}


@app.get("/api/jobs")
def list_jobs():
    return {"jobs": job_store.list_all()}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = job_store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job
