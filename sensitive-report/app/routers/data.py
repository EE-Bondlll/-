"""数据中枢 API：资产/风险批量写入、查询、状态更新、基线对比、任务记录。

全项目唯一数据入口，成员A 编排后统一走这里落库（见 contracts/api_contracts.md）。
"""
import hashlib
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import redact
from ..database import get_db
from ..models import Asset, Risk, Job, AuditLog

router = APIRouter(tags=["data"])


# ---------- 模型 ----------

class RiskIn(BaseModel):
    asset_url: str
    category: str
    severity: str
    title: str
    description: str | None = None
    evidence: dict = {}
    raw_output: str | None = None
    tool: str | None = None
    template: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    status: str = "active"
    signature: str | None = None
    job_id: str | None = None   # 扩展字段，便于报告按任务聚合


class RisksBatchIn(BaseModel):
    risks: list[RiskIn]
    job_id: str | None = None   # 顶层统一指定本次巡检任务


class AssetIn(BaseModel):
    url: str
    host: str | None = None
    fingerprint: dict = {}
    status_code: int | None = None
    page_hash: str | None = None
    title: str | None = None


class AssetsBatchIn(BaseModel):
    assets: list[AssetIn]


class RiskPatch(BaseModel):
    status: str | None = None
    ai_explanation: dict | None = None


class JobIn(BaseModel):
    job_type: str
    status: str = "pending"
    job_id: str | None = None
    target_scope: dict = {}
    triggered_by: str | None = None
    started_at: str | None = None
    finished_at: str | None = None


# ---------- 工具 ----------

def _signature(url: str, category: str, title: str, detail: str = "") -> str:
    """与成员A clients.py 完全一致的去重键。"""
    return hashlib.sha256(f"{url}|{category}|{title}|{detail}".encode()).hexdigest()


def _parse_dt(s: str | None):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


# ---------- 资产 ----------

@router.post("/data/assets/batch")
def write_assets(body: AssetsBatchIn, db: Session = Depends(get_db)):
    written, updated = 0, 0
    for a in body.assets:
        host = a.host or (a.url.split("//")[-1].split("/")[0] if "//" in a.url else a.url)
        existing = db.query(Asset).filter(Asset.url == a.url).first()
        if existing:
            existing.host = host
            existing.fingerprint = a.fingerprint
            existing.status_code = a.status_code
            existing.page_hash = a.page_hash or existing.page_hash
            existing.title = a.title
            existing.last_seen = datetime.now(timezone.utc)
            updated += 1
        else:
            db.add(Asset(url=a.url, host=host, fingerprint=a.fingerprint,
                         status_code=a.status_code, page_hash=a.page_hash, title=a.title))
            written += 1
    db.commit()
    return {"written": written, "updated": updated}


# ---------- 风险 ----------

@router.post("/data/risks/batch")
def write_risks(body: RisksBatchIn, db: Session = Depends(get_db)):
    """批量写入。signature 唯一约束：已存在则只更新 last_seen / status，不重复插入。"""
    inserted, updated = 0, 0
    for r in body.risks:
        sig = r.signature or _signature(r.asset_url, r.category, r.title,
                                        r.raw_output or "")
        existing = db.query(Risk).filter(Risk.signature == sig).first()
        if existing:
            existing.last_seen = datetime.now(timezone.utc)
            if r.status and r.status not in ("fixed",):
                existing.status = r.status
            updated += 1
            continue
        # 兜底脱敏：即使上游漏脱敏，落库前再打码一次，满足脱敏硬要求
        ev = dict(r.evidence or {})
        if ev.get("matched_context"):
            ev["matched_context"] = redact.redact(ev["matched_context"])
        db.add(Risk(
            asset_url=r.asset_url, category=r.category, severity=r.severity,
            title=r.title, description=r.description, evidence=ev,
            raw_output=r.raw_output, tool=r.tool, template=r.template,
            signature=sig, status=r.status,
            job_id=r.job_id or body.job_id,
            first_seen=_parse_dt(r.first_seen) or datetime.now(timezone.utc),
            last_seen=_parse_dt(r.last_seen) or datetime.now(timezone.utc),
        ))
        inserted += 1
    db.commit()
    return {"inserted": inserted, "updated": updated}


@router.patch("/data/risks/{risk_id}")
def patch_risk(risk_id: int, body: RiskPatch, db: Session = Depends(get_db)):
    risk = db.get(Risk, risk_id)
    if not risk:
        raise HTTPException(status_code=404, detail="risk not found")
    if body.status:
        risk.status = body.status
    if body.ai_explanation is not None:
        risk.ai_explanation = body.ai_explanation
    db.commit()
    return {"id": risk.id, "status": risk.status, "ai_explanation": risk.ai_explanation}


@router.get("/data/risks")
def query_risks(category: str | None = None,
                 severity: str | None = None,
                 status: str | None = None,
                 scope: str | None = None,
                 page: int = 1, page_size: int = 50,
                 db: Session = Depends(get_db)):
    q = db.query(Risk)
    if category:
        q = q.filter(Risk.category == category)
    if severity:
        q = q.filter(Risk.severity == severity)
    if status:
        q = q.filter(Risk.status == status)
    if scope:
        q = q.filter(Risk.asset_url.like(f"{scope}%"))
    total = q.count()
    rows = q.order_by(Risk.last_seen.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"total": total, "page": page, "page_size": page_size,
            "risks": [_risk_dict(r) for r in rows]}


def _risk_dict(r: Risk) -> dict:
    return {
        "id": r.id, "asset_url": r.asset_url, "category": r.category,
        "severity": r.severity, "title": r.title, "description": r.description,
        "evidence": r.evidence, "tool": r.tool, "template": r.template,
        "signature": r.signature, "status": r.status,
        "ai_explanation": r.ai_explanation, "job_id": r.job_id,
        "first_seen": r.first_seen.isoformat() if r.first_seen else None,
        "last_seen": r.last_seen.isoformat() if r.last_seen else None,
    }


# ---------- 基线对比 ----------

@router.get("/data/baseline-diff")
def baseline_diff(scope: str | None = None, db: Session = Depends(get_db)):
    """输出 新增 / 已修复 / 持续 三组。

    口径（不改动契约表结构，用 jobs 最新任务做时间分界）：
      - 新增：最近一次巡检任务 started_at 之后首次发现（first_seen >= 该时间）
      - 已修复：status == fixed
      - 持续：仍 active/confirmed，且 first_seen 早于最近任务开始时间（老问题仍在）
    若还没有任务记录，则全部风险归入"持续"。
    """
    q = db.query(Risk)
    if scope:
        q = q.filter(Risk.asset_url.like(f"{scope}%"))
    risks = q.all()

    latest = db.query(Job).order_by(Job.started_at.desc().nullslast()).first()
    boundary = latest.started_at if latest and latest.started_at else None

    new, fixed, persistent = [], [], []
    for r in risks:
        item = _risk_dict(r)
        if r.status == "fixed":
            fixed.append(item)
        elif boundary and r.first_seen and r.first_seen >= boundary:
            new.append(item)
        else:
            persistent.append(item)
    return {"boundary": boundary.isoformat() if boundary else None,
            "new": new, "fixed": fixed, "persistent": persistent}


# ---------- 任务 ----------

@router.post("/data/jobs")
def record_job(body: JobIn, db: Session = Depends(get_db)):
    job_id = body.job_id or uuid.uuid4().hex[:12]
    job = db.query(Job).filter(Job.job_id == job_id).first()
    if not job:
        job = Job(job_id=job_id, job_type=body.job_type)
        db.add(job)
    job.status = body.status
    job.target_scope = body.target_scope
    job.triggered_by = body.triggered_by
    job.started_at = _parse_dt(body.started_at) or job.started_at or datetime.now(timezone.utc)
    job.finished_at = _parse_dt(body.finished_at)
    db.commit()
    return {"job_id": job_id, "status": job.status}


@router.get("/data/jobs")
def list_jobs(limit: int = 50, db: Session = Depends(get_db)):
    rows = db.query(Job).order_by(Job.started_at.desc().nullslast()).limit(limit).all()
    return {"jobs": [{"job_id": j.job_id, "job_type": j.job_type, "status": j.status,
                      "triggered_by": j.triggered_by,
                      "started_at": j.started_at.isoformat() if j.started_at else None,
                      "finished_at": j.finished_at.isoformat() if j.finished_at else None}
                     for j in rows]}


@router.get("/data/stats/trend")
def risk_trend(days: int = 14, db: Session = Depends(get_db)):
    """按天聚合新增风险数，供 Dashboard 趋势折线图。"""
    from datetime import timedelta
    since = datetime.utcnow() - timedelta(days=days)
    rows = db.query(Risk).filter(Risk.first_seen >= since).all()
    buckets: dict[str, int] = {}
    for r in rows:
        if r.first_seen:
            day = r.first_seen.strftime("%Y-%m-%d")
            buckets[day] = buckets.get(day, 0) + 1
    dates = sorted(buckets.keys())
    return {"dates": dates, "counts": [buckets[d] for d in dates]}


# ---------- 审计 ----------

@router.get("/data/audit")
def list_audit(limit: int = 50, db: Session = Depends(get_db)):
    rows = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return {"audit": [{"operator": a.operator, "action": a.action, "target": a.target,
                       "detail": a.detail,
                       "created_at": a.created_at.isoformat() if a.created_at else None}
                      for a in rows]}
