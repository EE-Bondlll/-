"""成员C · 敏感信息与数据报告服务（FastAPI 入口）。

启动：uvicorn app.main:app --host 0.0.0.0 --port 8002
对接成员A：DATA_BASE_URL=http://sensitive-report:8002
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import os

from . import config, database
from .routers import data, rules, sensitive, semantic, alert, report
from .services import notifier


@asynccontextmanager
async def lifespan(_app: FastAPI):
    database.init_db()
    # 灌入内置默认规则
    db = database.SessionLocal()
    try:
        rules.seed_default_rules(db)
    finally:
        db.close()
    yield


app = FastAPI(title="Sensitive & Report Service", version=config.SERVICE_VERSION, lifespan=lifespan)

app.include_router(data.router)
app.include_router(rules.router)
app.include_router(sensitive.router)
app.include_router(semantic.router)
app.include_router(alert.router)
app.include_router(report.router)


@app.get("/")
def dashboard():
    """Dashboard 首页。"""
    tpl = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "templates", "dashboard.html")
    return FileResponse(tpl)


@app.get("/health")
def health():
    return {"status": "ok", "service": config.SERVICE_NAME, "version": config.SERVICE_VERSION}
