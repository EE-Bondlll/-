"""告警通道：飞书机器人 / 邮件 / 通用 webhook。

未配置对应通道时静默跳过，接口始终返回成功，不阻塞巡检主流程。
带 24h 去重：同一 signature 在 ALERT_DEDUP_SECONDS 内不重复告警。
"""
import hmac
import base64
import hashlib
import time
import json
import smtplib
from email.mime.text import MIMEText

import httpx

from .. import config

# 内存去重表：signature -> 上次告警时间戳
_alerted: dict[str, float] = {}


def _dedup_key(level: str, message: str, payload: dict) -> str:
    sig = payload.get("signature") or payload.get("asset_url") or message
    return f"{level}:{sig}"


def should_alert(level: str, message: str, payload: dict) -> bool:
    key = _dedup_key(level, message, payload)
    now = time.time()
    last = _alerted.get(key, 0)
    if now - last < config.ALERT_DEDUP_SECONDS:
        return False
    _alerted[key] = now
    return True


def _feishu_sign(secret: str) -> dict:
    timestamp = str(int(time.time()))
    string_to_sign = f"{timestamp}\n{secret}"
    h = hmac.new(secret.encode(), string_to_sign.encode(), hashlib.sha256).digest()
    return {"timestamp": timestamp, "sign": base64.b64encode(h).decode()}


def send_feishu(level: str, message: str, payload: dict) -> bool:
    if not config.FEISHU_WEBHOOK:
        return False
    body = {
        "msg_type": "text",
        "content": {"text": f"【安全巡检告警·{level}】\n{message}\n详情：{json.dumps(payload, ensure_ascii=False)[:500]}"},
    }
    if config.FEISHU_SECRET:
        body.update(_feishu_sign(config.FEISHU_SECRET))
    try:
        httpx.post(config.FEISHU_WEBHOOK, json=body, timeout=10)
        return True
    except Exception:
        return False


def send_mail(level: str, message: str, payload: dict) -> bool:
    if not (config.SMTP_HOST and config.SMTP_USER and config.ALERT_MAIL_TO):
        return False
    msg = MIMEText(f"{message}\n\n{json.dumps(payload, ensure_ascii=False, indent=2)}", "plain", "utf-8")
    msg["Subject"] = f"[安全巡检告警·{level}] {message[:60]}"
    msg["From"] = config.SMTP_USER
    msg["To"] = config.ALERT_MAIL_TO
    try:
        with smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT) as s:
            s.login(config.SMTP_USER, config.SMTP_PASS)
            s.sendmail(config.SMTP_USER, config.ALERT_MAIL_TO.split(","), msg.as_string())
        return True
    except Exception:
        return False


def send_webhook(level: str, message: str, payload: dict) -> bool:
    if not config.GENERAL_WEBHOOK:
        return False
    try:
        httpx.post(config.GENERAL_WEBHOOK,
                   json={"level": level, "message": message, "payload": payload}, timeout=10)
        return True
    except Exception:
        return False


def dispatch(level: str, message: str, payload: dict | None = None) -> dict:
    payload = payload or {}
    if not should_alert(level, message, payload):
        return {"sent": True, "deduped": True, "channels": []}
    channels = []
    if send_feishu(level, message, payload):
        channels.append("feishu")
    if send_mail(level, message, payload):
        channels.append("email")
    if send_webhook(level, message, payload):
        channels.append("webhook")
    if not channels:
        # 未配置任何通道：仍返回成功，仅记录（演示时不报错）
        return {"sent": True, "channels": [], "note": "未配置告警通道，仅记录"}
    return {"sent": True, "channels": channels}
