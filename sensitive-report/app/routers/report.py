"""报告接口：GET /report/{job_id}（HTML）、GET /report/{job_id}/export（PDF）。"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Job, Risk
from ..services import reporter

router = APIRouter(tags=["report"])


def _collect(job: Job, db: Session):
    """按 job 时间窗口聚合风险（fallback：按 job_id 字段过滤）。"""
    risks = db.query(Risk).filter(Risk.job_id == job.job_id).all()
    if not risks and job.started_at:
        q = db.query(Risk).filter(Risk.first_seen >= job.started_at)
        if job.finished_at:
            q = q.filter(Risk.first_seen <= job.finished_at)
        risks = q.all()
    return risks


def _risk_dict(r: Risk) -> dict:
    return {
        "asset_url": r.asset_url, "category": r.category, "severity": r.severity,
        "title": r.title, "description": r.description, "evidence": r.evidence,
        "ai_explanation": r.ai_explanation,
    }


def _job_dict(job: Job) -> dict:
    return {
        "job_id": job.job_id, "job_type": job.job_type, "status": job.status,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }


@router.get("/report/{job_id}", response_class=HTMLResponse)
def get_report(job_id: str, db: Session = Depends(get_db)):
    job = db.query(Job).filter(Job.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    risks = [_risk_dict(r) for r in _collect(job, db)]
    return reporter.render_html(_job_dict(job), risks)


@router.get("/report/{job_id}/export")
def export_report(job_id: str, format: str = "html", db: Session = Depends(get_db)):
    job = db.query(Job).filter(Job.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    risks = [_risk_dict(r) for r in _collect(job, db)]
    html = reporter.render_html(_job_dict(job), risks)
    if format == "pdf":
        try:
            pdf = reporter.render_pdf(html)
            return Response(content=pdf, media_type="application/pdf",
                            headers={"Content-Disposition": f"attachment; filename=report_{job_id}.pdf"})
        except Exception as e:
            # PDF 库不可用时回退 HTML，不报错
            return HTMLResponse(content=html, headers={"X-PDF-Fallback": str(e)[:200]})
    return HTMLResponse(content=html)


@router.get("/reports")
def list_reports(db: Session = Depends(get_db)):
    """历史报告归档索引：列出所有任务及对应报告链接。"""
    rows = db.query(Job).order_by(Job.started_at.desc().nullslast()).all()
    return {"reports": [
        {"job_id": j.job_id, "job_type": j.job_type, "status": j.status,
         "started_at": j.started_at.isoformat() if j.started_at else None,
         "report_url": f"/report/{j.job_id}"}
        for j in rows
    ]}
