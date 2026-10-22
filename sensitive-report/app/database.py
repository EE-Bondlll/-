"""SQLAlchemy 引擎与会话。PostgreSQL / SQLite 双模式由 config.DATABASE_URL 决定。"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from . import config

# SQLite 需要开启外键与线程检查
_connect_args = {}
if config.DATABASE_URL.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}
    os.makedirs(os.path.dirname(config.DATABASE_URL.replace("sqlite:///", "")), exist_ok=True)

engine = create_engine(config.DATABASE_URL, connect_args=_connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def get_db():
    """FastAPI 依赖注入：请求结束自动关会话。"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """建表（postgres 容器也会用 contracts/schema.sql 初始化，两者幂等）。"""
    from . import models  # noqa: F401 确保模型已导入
    Base.metadata.create_all(bind=engine)
