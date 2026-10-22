"""POST /scan/sensitive —— 敏感信息检测入口。

成员A 编排调用。请求体与契约一致：{"assets":[...],"config":{"rules":[...]}}
若 config.rules 为空，则自动从数据库启用规则库加载。
"""
import uuid

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import SensitiveRule
from ..services import sensitive_engine

router = APIRouter(tags=["sensitive"])


def _load_active_rules(db: Session) -> list[dict]:
    rows = db.query(SensitiveRule).filter(SensitiveRule.enabled.is_(True),
                                          SensitiveRule.rule_type != "sample").all()
    return [{"type": r.rule_type, "name": r.name, "pattern": r.pattern,
             "severity": r.severity} for r in rows]


@router.post("/scan/sensitive")
def scan_sensitive(body: dict, db: Session = Depends(get_db)):
    assets = body.get("assets", [])
    config = body.get("config", {}) or {}
    rules = config.get("rules") or _load_active_rules(db)

    all_risks = []
    with httpx.Client() as client:
        for a in assets:
            url = a.get("url") if isinstance(a, dict) else str(a)
            all_risks.extend(sensitive_engine.scan_url(url, rules, client))

    return {"job_id": uuid.uuid4().hex[:12], "risks": all_risks}


@router.get("/health")
def health():
    return {"status": "ok", "service": "sensitive-report"}
