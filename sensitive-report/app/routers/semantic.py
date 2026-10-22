"""POST /semantic/leak-check —— LLM 语义泄露二级研判。"""
from fastapi import APIRouter
from pydantic import BaseModel

from ..services import llm

router = APIRouter(tags=["semantic"])


class LeakCheckIn(BaseModel):
    context: str
    rule: str = ""


@router.post("/semantic/leak-check")
def leak_check(body: LeakCheckIn):
    return llm.check_leak(body.context, body.rule)
