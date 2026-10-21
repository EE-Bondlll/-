"""Agent Core - 智能巡检编排服务（v0.5）

已实现：
- 4.1 配置管理 / 敏感规则管理 / 样例上传 / 校验
- 4.2 巡检计划（LLM 优先 + 规则兜底）/ 指纹策略路由 / 调用容错
- 4.3 编排执行：手动巡检（后台线程执行，pending→running→done/failed）、
  定时巡检（APScheduler cron 到点自动执行）、白名单校验、QPS 限速、审计日志
- 4.5 AI 误报研判：规则版 + LLM 版（失败降级）+ 三段式解释
- 4.6 闭环功能：基线对比（新增/已修复/持续）、复测队列（受影响资产重扫、
  未命中自动消警置 fixed）、告警触发（级别阈值 + 24h 去重 + 事件留痕）

运行：uvicorn app.main:app --reload --port 8000
"""
import os
import re
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, UploadFile, File, Header, Body
from pydantic import BaseModel, Field, field_validator

from . import clients, ledger as ledger_mod, orchestrator, planner, rules, scheduler, storage


@asynccontextmanager
async def lifespan(_app: FastAPI):
    scheduler.start_scheduler()
    yield
    scheduler.shutdown()


app = FastAPI(title="Agent Core - 智能巡检编排服务", version="0.5.0", lifespan=lifespan)

# 存储后端（当前 JSON 文件；PG 就绪后换成 PGStore 实现同接口即可）
config_store = storage.FileStore(storage.CONFIGS_FILE)
job_store = storage.FileStore(storage.JOBS_FILE)
audit_store = storage.FileStore(storage.AUDIT_FILE)
rule_store = rules.RuleStore()

# 编排执行器（当前 MOCK_MODE=1：调用 mock 检测器；B/C 就绪后设 MOCK_MODE=0 切换真实服务）
orchestrator_engine = orchestrator.Orchestrator(clients.DetectorClient(), clients.DataClient())

# 风险账本（4.6）：基线对比 / 复测队列 / 告警事件
ledger_engine = ledger_mod.Ledger()

# ---------- 校验 ----------

_DOMAIN_RE = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_VALID_SCOPES = {"full", "subdomains", "paths"}


def validate_config(cfg: dict):
    if not cfg.get("domains"):
        raise HTTPException(status_code=422, detail="domains 不能为空")
    bad = [d for d in cfg["domains"] if not (_DOMAIN_RE.match(d) or _IPV4_RE.match(d))]
    if bad:
        raise HTTPException(status_code=422, detail=f"域名/IP 格式非法: {bad}")
    if cfg.get("scope") not in _VALID_SCOPES:
        raise HTTPException(status_code=422, detail=f"scope 必须为 {sorted(_VALID_SCOPES)} 之一")
    if not re.match(r"^(\S+\s+){4}\S+$", cfg.get("cron", "")):
        raise HTTPException(status_code=422, detail=f"cron 表达式格式非法: {cfg.get('cron')}")


# ---------- 模型 ----------

class Config(BaseModel):
    domains: list[str] = Field(min_length=1, description="授权域名（白名单）")
    scope: str = "full"
    cron: str = "0 2 * * *"
    sensitive_rules: list[str] = []


class PlanRequest(BaseModel):
    config_id: str


class JobStartRequest(BaseModel):
    config_id: str = ""  # 兼容 query 参数：body 可缺省，由 start_job 兜底取 query


class RetestRequest(BaseModel):
    config_id: str


class RuleIn(BaseModel):
    rule_type: str
    name: str
    pattern: str = ""
    severity: str = "medium"
    enabled: bool = True


class RulePatch(BaseModel):
    pattern: str | None = None
    severity: str | None = None
    enabled: bool | None = None


# ---------- 审计 ----------

def _audit(action: str, target: str, detail: dict):
    entry = {
        "operator": "system",
        "action": action,
        "target": target,
        "detail": detail,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    audit_store.save(uuid.uuid4().hex[:12], entry)


# ---------- 工具凭证与格式化（防模型编造） ----------

def _new_trace() -> str:
    """本次调用唯一凭证：模型回答末尾必须原样引用，用于事后校验是否真实调用。"""
    return uuid.uuid4().hex[:12]


def _format_job_report(job: dict) -> str:
    """将巡检任务结果格式化为可直接展示的文本（模型只允许引用，不得改写）。"""
    status = job.get("status", "unknown")
    result = job.get("result") or {}
    risks = result.get("risks") or []
    high = sum(1 for r in risks if r.get("severity") == "high")
    medium = sum(1 for r in risks if r.get("severity") == "medium")
    low = sum(1 for r in risks if r.get("severity") == "low")
    lines = [
        f"巡检任务 {job.get('job_id')} 状态：{status}",
        f"共发现 {len(risks)} 项风险（高危 {high}、中危 {medium}、低危 {low}）",
    ]
    for i, r in enumerate(risks, 1):
        lines.append(f"{i}. [{r.get('severity')}] {r.get('title')} —— {r.get('asset_url')}")
    return "\n".join(lines)


# ---------- 任务执行 ----------

def _run_job(job_id: str, config_id: str, plan: dict):
    """后台执行一次巡检：pending → running → done/failed；完成后入账（4.6）。"""
    job = job_store.get(job_id)
    job["status"] = "running"
    job_store.save(job_id, job)
    _audit("scan_start", config_id, {"plan_id": plan["plan_id"], "job_id": job_id})
    try:
        result = orchestrator_engine.run(plan, config_id)
        # 4.6 闭环入账：按任务类型走基线对比或复测消警
        job_type = job.get("job_type", "manual")
        risks = result.get("risks", [])
        if job_type == "retest":
            retest = ledger_engine.apply_retest(
                config_id, plan.get("targets", []), risks, job_id)
            result["retest"] = retest
            _audit("retest_done", config_id,
                   {"job_id": job_id, "cleared": len(retest["cleared"]),
                    "still_active": len(retest["still_active"]),
                    "newly_found": len(retest["newly_found"])})
        else:
            baseline = ledger_engine.apply_full(config_id, risks, job_id)
            result["baseline"] = baseline
            alerts = ledger_engine.evaluate_alerts(config_id, risks)
            if alerts:
                result["alerts"] = alerts
                _audit("alert_triggered", config_id,
                       {"job_id": job_id, "count": len(alerts),
                        "levels": sorted({a["level"] for a in alerts})})
            _audit("baseline_done", config_id,
                   {"job_id": job_id, "new": len(baseline["new"]),
                    "fixed": len(baseline["fixed"]),
                    "persistent": len(baseline["persistent"])})
        job = job_store.get(job_id)
        job["status"] = "done"
        job["finished_at"] = datetime.now(timezone.utc).isoformat()
        job["result"] = result
        job_store.save(job_id, job)
        _audit("scan_done", config_id,
               {"job_id": job_id, "risks": result.get("risks_after_dedup"),
                "high_count": result.get("high_count")})
    except Exception as e:
        job = job_store.get(job_id)
        job["status"] = "failed"
        job["finished_at"] = datetime.now(timezone.utc).isoformat()
        job["error"] = str(e)[:500]
        job_store.save(job_id, job)
        _audit("scan_failed", config_id, {"job_id": job_id, "error": str(e)[:200]})


def _spawn_job(job_type: str, config_id: str, plan: dict) -> dict:
    job = {
        "job_id": uuid.uuid4().hex[:12],
        "job_type": job_type,                # manual | scheduled | retest
        "config_id": config_id,
        "plan_id": plan["plan_id"],
        "status": "pending",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "plan": plan,
    }
    job_store.save(job["job_id"], job)
    threading.Thread(target=_run_job, args=(job["job_id"], config_id, plan), daemon=True).start()
    return job


def _scheduled_run(config_id: str):
    """定时巡检回调：读配置 → 生成计划 → 后台执行（与手动同一链路）。"""
    cfg = config_store.get(config_id)
    if cfg is None:
        return
    plan = planner.create_planner().build_plan(cfg)
    _spawn_job("scheduled", config_id, plan)


# ---------- 健康检查 ----------

@app.get("/health")
def health():
    return {"status": "ok", "service": "agent-core", "version": app.version}


# ---------- 4.1 配置管理 ----------

# 管理员口令：部署时通过环境变量 ADMIN_TOKEN 注入；未设置时为演示默认值
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "SecInspector@2026")


class AuthorizeRequest(BaseModel):
    domains: list[str] | str = Field(default_factory=list, description="待授权域名/IP 列表（支持数组或逗号分隔字符串）")
    scope: str = "full"
    cron: str = "0 2 * * *"
    sensitive_rules: list[str] = []
    admin_token: str = ""  # 兼容请求头与 body 两种认证方式

    @field_validator("domains", mode="before")
    @classmethod
    def split_domains(cls, v):
        if isinstance(v, str):
            return [d.strip() for d in v.replace("，", ",").split(",") if d.strip()]
        return v


@app.post("/api/authorize")
def authorize_config(
    req: AuthorizeRequest | None = Body(default=None),
    domains: str = "",
    scope: str = "full",
    admin_token: str = "",
    x_admin_token: str = Header(default=""),
):
    """恒脑工具：管理员认证后新增授权站点（身份校验 + 幂等 + 审计留痕）。
    兼容三种调用方式：JSON body / query 参数（恒脑平台探测用 query 传参）/ 请求头口令。"""
    if req is not None:
        data = req.model_dump()
        if domains.strip() and not data["domains"]:
            data["domains"] = [d.strip() for d in domains.split(",") if d.strip()]
        if not data["admin_token"]:
            data["admin_token"] = admin_token
    else:
        data = {"domains": [d.strip() for d in domains.split(",") if d.strip()],
                "scope": scope or "full",
                "cron": "0 2 * * *",
                "sensitive_rules": [],
                "admin_token": admin_token}
    token = (data.get("admin_token") or x_admin_token or "").strip()
    # 空 domains = 平台连通性探测：返回 200 但不创建任何配置（无副作用，安全）
    if not data["domains"]:
        return {"ok": True, "config_id": "probe", "saved": True, "probe": True,
                "domains": [], "trace": _new_trace()}
    # 无有效口令：返回 200 探测响应、不创建配置（恒脑调试探测兼容；真实授权必须带口令）
    if token != ADMIN_TOKEN:
        return {"ok": False, "config_id": "probe", "saved": False, "probe": True,
                "reason": "auth_missing", "domains": data["domains"], "trace": _new_trace()}
    validate_config(data)
    config_id = storage.make_config_id(data["domains"])
    config_store.save(config_id, data)
    scheduler.schedule_inspection(config_id, data["cron"], _scheduled_run)
    _audit("config_authorized", config_id,
           {"domains": data["domains"], "scope": data["scope"], "by": "admin_api"})
    return {"ok": True, "config_id": config_id, "saved": True,
            "authorized_domains": ",".join(data["domains"]),
            "domains": data["domains"], "trace": _new_trace()}


@app.post("/api/config")
def save_config(cfg: Config):
    """录入巡检授权配置（幂等），并按 cron 注册/更新定时巡检。"""
    data = cfg.model_dump()
    validate_config(data)
    config_id = storage.make_config_id(data["domains"])
    config_store.save(config_id, data)
    scheduler.schedule_inspection(config_id, data["cron"], _scheduled_run)
    _audit("config_change", config_id, {"domains": data["domains"], "cron": data["cron"]})
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
    if file.filename is None or file.filename == "":
        raise HTTPException(status_code=422, detail="文件名不能为空")
    meta = rules.save_sample(await file.read(), file.filename)
    return {"saved": True, **meta}


# ---------- 4.2 巡检计划与策略路由 ----------

@app.post("/api/plan")
def make_plan(req: PlanRequest):
    cfg = config_store.get(req.config_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail="config not found")
    return planner.create_planner().build_plan(cfg)


@app.post("/api/strategy")
def strategy_for(fp: dict):
    return {"fingerprint": fp, "steps": planner.route_strategy(fp)}


@app.get("/api/llm/status")
def llm_status():
    p = planner.LLMPlanner()
    return {
        "mode": "llm" if p.available() else "rule",
        "llm_configured": p.available(),
        "base_url": p.base_url,
        "model": p.model,
        "note": "设置环境变量 LLM_API_KEY 后启用 LLM 规划与研判（恒脑/DeepSeek OpenAI 兼容接口）",
    }


# ---------- 4.5 AI 误报研判 ----------

@app.post("/api/review")
def review_risks(risks: list[dict]):
    """对风险列表做误报研判：返回带 status / ai_explanation 的更新结果（供演示与自测）。"""
    return {"mode": orchestrator_engine.reviewer.mode,
            "reviewed": orchestrator_engine.reviewer.review(risks)}


# ---------- 4.6 闭环功能：基线对比 / 复测队列 / 告警 ----------

def _format_baseline(diff: dict) -> str:
    """将基线对比结果格式化为可直接展示的文本（避免模型混淆 new/fixed/persistent）。"""
    new_items = diff.get("new", []) or []
    fixed_items = diff.get("fixed", []) or []
    persistent_items = diff.get("persistent", []) or []
    lines = [
        f"基线对比报告（scan_mode={diff.get('scan_mode')}，job_id={diff.get('job_id')}）",
        f"新增风险：{len(new_items)} 项",
        f"已修复风险：{len(fixed_items)} 项",
        f"持续风险：{len(persistent_items)} 项",
    ]
    for label, items in (("新增", new_items),
                         ("已修复", fixed_items),
                         ("持续", persistent_items)):
        if items:
            lines.append(f"\n【{label}风险清单】")
            for i, r in enumerate(items, 1):
                lines.append(
                    f"{i}. [{r.get('severity')}] {r.get('title')} —— {r.get('asset_url')}")
    return "\n".join(lines)


@app.get("/api/baseline")
def get_baseline(config_id: str):
    """最近一次全量巡检的基线对比报告（直接返回格式化文本，避免模型误读数组）。"""
    diff = ledger_engine.last_baseline(config_id)
    if diff is None:
        raise HTTPException(status_code=404,
                            detail="尚无基线数据：请先对该 config 执行一次全量巡检")
    return {
        "ok": True,
        "config_id": config_id,
        "scan_mode": diff.get("scan_mode"),
        "job_id": diff.get("job_id"),
        "computed_at": diff.get("computed_at"),
        "report_text": _format_baseline(diff),
        "trace": _new_trace(),
    }


@app.get("/api/retest/targets")
def retest_targets(config_id: str):
    """复测队列的受影响资产：当前 status=active 风险所属资产（去重）。"""
    targets = ledger_engine.retest_targets(config_id)
    return {"config_id": config_id, "targets": targets, "count": len(targets)}


@app.post("/api/retest")
def start_retest(req: RetestRequest):
    """发起复测：仅重扫受影响资产；未再命中的风险自动消警（置 fixed）。"""
    cfg = config_store.get(req.config_id)
    if cfg is None:
        raise HTTPException(status_code=404, detail="config not found")
    targets = ledger_engine.retest_targets(req.config_id)
    if not targets:
        return {"job": None,
                "note": "无待复测风险（该 config 下账本无 active 风险）",
                "targets": []}
    plan = planner.create_planner().build_plan(cfg)
    plan["targets"] = targets
    plan["note"] = f"复测队列：{len(targets)} 个受影响资产"
    job = _spawn_job("retest", req.config_id, plan)
    return {"job": job, "targets": targets, "count": len(targets)}


@app.get("/api/alerts")
def list_alerts(limit: int = 50):
    """告警事件记录（含触发规则、级别、去重窗口）。"""
    return {"alerts": ledger_engine.list_alerts(limit)}


# ---------- 4.3 任务入口与调度 ----------

@app.post("/api/jobs/start")
def start_job(req: JobStartRequest | None = None, config_id: str | None = None):
    """手动发起一次巡检：生成计划 → 后台执行 → 立即返回 job_id。

    兼容两种参数传递：JSON body {"config_id": "..."}（标准）或 URL query ?config_id=...（恒脑平台 API 工具采用的方式）。
    """
    cid = (req.config_id if req else "") or config_id or ""
    if not cid:
        raise HTTPException(status_code=422, detail="config_id 必填（body 或 query）")
    cfg = config_store.get(cid)
    if cfg is None:
        raise HTTPException(status_code=404, detail="config not found")
    plan = planner.create_planner().build_plan(cfg)
    job = _spawn_job("manual", cid, plan)
    return {"ok": True, "job_id": job["job_id"], "status": job["status"],
            "plan": plan, "message": "巡检任务已创建", "trace": _new_trace()}


@app.get("/api/jobs")
def list_jobs(job_id: str | None = None):
    """任务查询；兼容恒脑平台 query 传参：GET /api/jobs?job_id=xxx 返回单个任务详情。

    未提供 job_id 时兜底返回最近一次任务（避免模型因猜不出 ID 而放弃调用）。
    """
    jobs = job_store.list_all()
    if job_id:
        job = job_store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        job = dict(job)
        job["report_text"] = _format_job_report(job)
        job["trace"] = _new_trace()
        return job
    if not jobs:
        return {"ok": False, "message": "尚无巡检任务，请先发起一次巡检",
                "trace": _new_trace()}
    latest = max(jobs, key=lambda j: j.get("started_at") or "")
    latest = dict(latest)
    latest["report_text"] = _format_job_report(latest)
    latest["trace"] = _new_trace()
    return latest


@app.get("/api/jobs/latest")
def latest_job(config_id: str | None = None):
    """最近一次巡检任务详情；可按 config_id 过滤（供工作流/工具节点兜底取 job_id）。"""
    jobs = job_store.list_all()
    if config_id:
        jobs = [j for j in jobs if j.get("config_id") == config_id]
    if not jobs:
        return {"ok": False, "message": "尚无巡检任务，请先发起一次巡检",
                "trace": _new_trace()}
    latest = max(jobs, key=lambda j: j.get("started_at") or "")
    latest = dict(latest)
    latest["report_text"] = _format_job_report(latest)
    latest["trace"] = _new_trace()
    return latest


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = job_store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job


@app.get("/api/scheduler/jobs")
def scheduler_jobs():
    """查看已注册的定时巡检任务。"""
    return {"scheduled": scheduler.list_scheduled_jobs()}


@app.get("/api/audit")
def list_audit(limit: int = 50):
    entries = audit_store.list_all()
    entries.sort(key=lambda e: e.get("created_at", ""), reverse=True)
    return {"audit": entries[:limit]}
