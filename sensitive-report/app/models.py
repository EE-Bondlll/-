"""ORM 模型，字段与 contracts/schema.sql 对齐。

JSONB 在 SQLite 下没有原生类型，统一用 sqlalchemy.JSON，PG 上会映射为 JSONB。
"""
from datetime import datetime

from sqlalchemy import (Boolean, Column, DateTime, BigInteger, ForeignKey,
                        Index, Integer, String, Text)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.types import JSON

from .database import Base

# PG 用 JSONB，SQLite 用 JSON —— 运行时按方言选择
JSONType = JSON().with_variant(JSONB(), "postgresql")

# 跨方言自增主键：PG 用 BIGSERIAL，SQLite 用 INTEGER PRIMARY KEY AUTOINCREMENT
PK = BigInteger().with_variant(Integer, "sqlite")


class Asset(Base):
    __tablename__ = "assets"
    id = Column(PK, primary_key=True, autoincrement=True)
    url = Column(Text, unique=True, nullable=False, index=True)
    host = Column(Text, nullable=False)
    fingerprint = Column(JSONType, default=dict)
    status_code = Column(Integer)
    page_hash = Column(Text)
    title = Column(Text)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Risk(Base):
    __tablename__ = "risks"
    id = Column(PK, primary_key=True, autoincrement=True)
    asset_url = Column(Text, nullable=False, index=True)
    category = Column(Text, nullable=False)
    severity = Column(Text, nullable=False)
    title = Column(Text, nullable=False)
    description = Column(Text)
    evidence = Column(JSONType, default=dict)
    raw_output = Column(Text)
    tool = Column(Text)
    template = Column(Text)
    signature = Column(Text, unique=True, nullable=False, index=True)
    status = Column(Text, default="active", index=True)
    ai_explanation = Column(JSONType, default=dict)
    # 扩展字段（契约只增不改）：记录该风险由哪次巡检写入，便于报告按任务聚合
    job_id = Column(Text, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Baseline(Base):
    __tablename__ = "baselines"
    id = Column(PK, primary_key=True, autoincrement=True)
    asset_url = Column(Text, nullable=False, index=True)
    page_hash = Column(Text, nullable=False)
    snapshot_ref = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_current = Column(Boolean, default=True)


class Job(Base):
    __tablename__ = "jobs"
    id = Column(PK, primary_key=True, autoincrement=True)
    job_id = Column(Text, unique=True, index=True)
    job_type = Column(Text, nullable=False)
    target_scope = Column(JSONType, default=dict)
    status = Column(Text, default="pending")
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    triggered_by = Column(Text)
    report_ref = Column(Text)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(PK, primary_key=True, autoincrement=True)
    operator = Column(Text, nullable=False)
    action = Column(Text, nullable=False)
    target = Column(Text)
    detail = Column(JSONType, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class SensitiveRule(Base):
    __tablename__ = "sensitive_rules"
    id = Column(PK, primary_key=True, autoincrement=True)
    rule_type = Column(Text, nullable=False)   # keyword | regex | file_type | sample
    name = Column(Text, nullable=False)
    pattern = Column(Text)
    severity = Column(Text, default="medium")
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


Index("idx_risks_asset", Risk.asset_url)
Index("idx_risks_status", Risk.status)
