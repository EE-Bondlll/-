"""报告渲染：按 job_id 聚合风险，生成 HTML / PDF。"""
import os
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import redact

TPL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "templates")
_env = Environment(loader=FileSystemLoader(TPL_DIR), autoescape=select_autoescape(["html"]))


def render_html(job: dict, risks: list[dict]) -> str:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    leak_count = 0
    for r in risks:
        sev = r.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1
        if r.get("category") == "leak":
            leak_count += 1
        # 二次脱敏兜底
        ev = r.get("evidence") or {}
        if ev.get("matched_context"):
            ev["matched_context"] = redact.redact(ev["matched_context"])
    tpl = _env.get_template("report.html")
    return tpl.render(job=job, risks=risks, counts=counts, leak_count=leak_count)


def render_pdf(html: str) -> bytes:
    """HTML → PDF。weasyprint 不可用时抛错，由调用方回退为 HTML。"""
    from weasyprint import HTML  # 延迟导入：Windows 上若无原生依赖，不阻塞服务启动
    return HTML(string=html).write_pdf()
