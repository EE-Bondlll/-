"""POST /alert/send —— 告警入口。"""
from fastapi import APIRouter
from pydantic import BaseModel

from ..services import notifier

router = APIRouter(tags=["alert"])


class AlertIn(BaseModel):
    level: str = "medium"
    message: str = ""
    payload: dict = {}


@router.post("/alert/send")
def send_alert(body: AlertIn):
    return notifier.dispatch(body.level, body.message, body.payload)
