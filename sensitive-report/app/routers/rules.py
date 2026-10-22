"""规则库管理 API：关键词 / 正则 / 文件类型 / 样例 规则增删改查。

与 contracts 对齐：GET/POST/PUT/DELETE /api/rules，POST /api/rules/sample。
内置一批常用规则作为默认库，首次启动时自动灌入。
"""
import hashlib
import os

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import SensitiveRule, AuditLog


def _audit(db: Session, action: str, target: str, detail: dict):
    db.add(AuditLog(operator="system", action=action, target=target, detail=detail))

router = APIRouter(prefix="/api/rules", tags=["rules"])

RULE_TYPES = {"keyword", "regex", "file_type", "sample"}

# 内置默认规则（可后续通过 API 修改/停用）
DEFAULT_RULES = [
    ("keyword", "数据库口令关键词", "DB_PASSWORD", "high"),
    ("keyword", "私钥关键词", "PRIVATE KEY", "critical"),
    ("keyword", "云密钥关键词", "AWS_SECRET_ACCESS_KEY", "critical"),
    ("regex", "中国大陆身份证号", r"\b\d{6}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]\b", "high"),
    ("regex", "手机号", r"\b1[3-9]\d{9}\b", "medium"),
    ("regex", "邮箱", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "low"),
    ("regex", "AWS Access Key", r"\bAKIA[0-9A-Z]{16}\b", "critical"),
    ("regex", "JWT 令牌", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b", "high"),
    ("regex", "私钥块", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "critical"),
    ("file_type", "环境变量文件", ".env", "high"),
    ("file_type", "备份文件", ".bak", "medium"),
    ("file_type", "SQL 导出", ".sql", "high"),
    ("file_type", "git 目录泄露", ".git/config", "high"),
]


class RuleIn(BaseModel):
    rule_type: str
    name: str
    pattern: str = ""
    severity: str = "medium"
    enabled: bool = True


class RulePatch(BaseModel):
    name: str | None = None
    pattern: str | None = None
    severity: str | None = None
    enabled: bool | None = None


def seed_default_rules(db: Session):
    if db.query(SensitiveRule).count() == 0:
        for rt, name, pat, sev in DEFAULT_RULES:
            db.add(SensitiveRule(rule_type=rt, name=name, pattern=pat, severity=sev))
        db.commit()


@router.get("")
def list_rules(rule_type: str | None = None, enabled: bool | None = None,
              db: Session = Depends(get_db)):
    q = db.query(SensitiveRule)
    if rule_type:
        q = q.filter(SensitiveRule.rule_type == rule_type)
    if enabled is not None:
        q = q.filter(SensitiveRule.enabled == enabled)
    rows = q.all()
    return {"rules": [{"id": r.id, "rule_type": r.rule_type, "name": r.name,
                       "pattern": r.pattern, "severity": r.severity,
                       "enabled": r.enabled} for r in rows]}


@router.post("")
def add_rule(rule: RuleIn, db: Session = Depends(get_db)):
    if rule.rule_type not in RULE_TYPES:
        raise HTTPException(status_code=422, detail=f"rule_type 必须为 {sorted(RULE_TYPES)} 之一")
    if rule.rule_type != "sample" and not rule.pattern:
        raise HTTPException(status_code=422, detail="keyword/regex/file_type 规则必须提供 pattern")
    r = SensitiveRule(rule_type=rule.rule_type, name=rule.name, pattern=rule.pattern,
                      severity=rule.severity, enabled=rule.enabled)
    db.add(r)
    db.flush()
    _audit(db, "rule_add", f"rule:{r.id}", {"name": r.name, "type": r.rule_type})
    db.commit()
    return {"id": r.id, "saved": True}


@router.put("/{rule_id}")
def update_rule(rule_id: int, patch: RulePatch, db: Session = Depends(get_db)):
    r = db.get(SensitiveRule, rule_id)
    if not r:
        raise HTTPException(status_code=404, detail="rule not found")
    for k, v in patch.model_dump(exclude_none=True).items():
        setattr(r, k, v)
    _audit(db, "rule_update", f"rule:{rule_id}", patch.model_dump(exclude_none=True))
    db.commit()
    return {"id": r.id, "updated": True}


@router.delete("/{rule_id}")
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    r = db.get(SensitiveRule, rule_id)
    if not r:
        raise HTTPException(status_code=404, detail="rule not found")
    _audit(db, "rule_delete", f"rule:{rule_id}", {"name": r.name})
    db.delete(r)
    db.commit()
    return {"id": rule_id, "deleted": True}


@router.post("/sample")
async def upload_sample(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """上传样例文件：记录其内容指纹，后续用于相似度比对。"""
    content = await file.read()
    fp = hashlib.sha256(content).hexdigest()
    sample_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "samples")
    os.makedirs(sample_dir, exist_ok=True)
    path = os.path.join(sample_dir, f"{fp[:16]}_{file.filename}")
    with open(path, "wb") as f:
        f.write(content)
    r = SensitiveRule(rule_type="sample", name=file.filename, pattern=fp, severity="high")
    db.add(r)
    db.commit()
    return {"saved": True, "sample_id": r.id, "sha256": fp, "bytes": len(content)}
