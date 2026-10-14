"""定时巡检调度（任务书 4.3）：基于 APScheduler 的 cron 调度。

POST /api/config 保存配置后，按 cfg.cron 注册/更新定时任务；
到点自动执行一次完整巡检（复用 Orchestrator，与手动巡检同一执行链路）。
"""
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import logging

logger = logging.getLogger("agent-core.scheduler")
scheduler = BackgroundScheduler(timezone="Asia/Shanghai")


def start_scheduler():
    if not scheduler.running:
        scheduler.start()
        logger.info("scheduler started")


def shutdown():
    """停止调度器（幂等）。lifespan 退出时调用。"""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("scheduler stopped")


def schedule_inspection(config_id: str, cron_expr: str, run_callback):
    """注册定时巡检。cron_expr 为空/禁用则跳过。已注册的同 config 任务先移除再注册（幂等）。"""
    if not cron_expr or cron_expr.lower() in ("", "disabled", "none"):
        remove_inspection(config_id)
        return
    job_id = f"inspection:{config_id}"
    try:
        trigger = CronTrigger.from_crontab(cron_expr)
    except ValueError:
        logger.warning("invalid cron expr %r, skip scheduling", cron_expr)
        return
    remove_inspection(config_id)
    scheduler.add_job(
        run_callback,
        trigger=trigger,
        id=job_id,
        replace_existing=True,
        kwargs={"config_id": config_id},
        coalesce=True,          # 错过的触发合并为一次，避免积压
        max_instances=1,        # 同一任务不并发
    )
    logger.info("scheduled inspection %s at %s", config_id, cron_expr)


def remove_inspection(config_id: str):
    job_id = f"inspection:{config_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)


def list_scheduled_jobs() -> list[dict]:
    return [
        {"job_id": j.id, "next_run": str(j.next_run_time) if j.next_run_time else None}
        for j in scheduler.get_jobs()
    ]
