"""AI 误报研判与三段式解释（任务书 4.5）。

- 规则版（RuleReviewer）：无需 API Key，按确定性规则研判
  （证据完整性、占位/测试数据特征、严重度），保证无大模型时闭环可用。
- LLM 版（LLMReviewer）：调用 OpenAI 兼容接口（恒脑/DeepSeek）逐条研判，
  输出 verdict / confidence / explanation{evidence_summary, impact, remediation}；
  调用失败自动降级规则版（mode=rule_fallback）。

研判输出约定（对齐 contracts/risk_schema.json）：
- status: active → confirmed | false_positive | unconfirmed
- ai_explanation: {"evidence_summary", "impact", "remediation", "mode"}
"""
import json
import os
from datetime import datetime, timezone

# 明显占位 / 测试数据特征（命中判 false_positive）
_PLACEHOLDER_HINTS = ("placeholder", "lorem ipsum", "dummy", "test data",
                      "测试数据", "示例数据", "占位", "for example only", "xxxxxx")


def _has_placeholder(text: str) -> bool:
    t = (text or "").lower()
    return any(h in t for h in _PLACEHOLDER_HINTS)


def _evidence_complete(risk: dict) -> bool:
    ev = risk.get("evidence") or {}
    return bool(ev.get("request_sample") or ev.get("response_sample")
                or ev.get("matched_context") or ev.get("screenshot_ref"))


class RuleReviewer:
    """确定性研判：先查占位特征 → 再查证据完整性 → 按严重度定论。"""

    mode = "rule"

    def review(self, risks: list[dict]) -> list[dict]:
        for r in risks:
            title = r.get("title", "")
            desc = r.get("description", "")
            if _has_placeholder(f"{title} {desc}"):
                r["status"] = "false_positive"
                r["ai_explanation"] = {
                    "evidence_summary": "内容命中占位/测试数据特征，判定为误报",
                    "impact": "无实际影响",
                    "remediation": "无需处理",
                    "mode": "rule",
                }
                continue
            if not _evidence_complete(r):
                r["status"] = "unconfirmed"
                r["ai_explanation"] = {
                    "evidence_summary": "证据不完整（缺少请求/响应样本或命中上下文），待人工复核",
                    "impact": "待确认",
                    "remediation": "建议人工访问目标资产复核后确认",
                    "mode": "rule",
                }
                continue
            r["status"] = "confirmed"
            sev = r.get("severity", "medium")
            r["ai_explanation"] = {
                "evidence_summary": f"检测器 {r.get('tool', '-')} 命中 {r.get('template', '-')}，证据完整",
                "impact": _impact_by_category(r.get("category", ""), sev),
                "remediation": _remediation_by_category(r.get("category", "")),
                "mode": "rule",
            }
        return risks


def _impact_by_category(category: str, severity: str) -> str:
    base = {
        "vuln": "攻击者可利用该漏洞获取敏感数据或控制站点",
        "weak_config": "配置缺陷可能被利用扩大攻击面",
        "tamper": "页面内容被篡改，影响公信力或传播恶意内容",
        "malware": "站点被植入恶意代码，访问者面临挂马风险",
        "bad_link": "页面存在恶意外链，可能诱导访问者进入钓鱼或恶意站点",
        "leak": "敏感信息（口令/密钥/个人信息）暴露，存在泄露与滥用风险",
    }
    return f"{base.get(category, '存在安全风险')}（严重度 {severity}）"


def _remediation_by_category(category: str) -> str:
    return {
        "vuln": "升级组件/修复漏洞；如无法立即修复，先用 WAF 规则临时封堵并评估暴露面",
        "weak_config": "按安全基线加固：补充安全响应头、启用 TLS1.2+、关闭不必要服务",
        "tamper": "定位篡改来源并清除，恢复官方内容；检查 CMS/中间件是否存在被入侵痕迹",
        "malware": "清除恶意脚本与外链，排查入侵路径（弱口令/漏洞利用），强化服务器防护",
        "bad_link": "移除或下线含恶意外链的页面，检查该页面上传/编辑权限是否被滥用",
        "leak": "立即下线暴露文件并修改其中泄露的口令/密钥；排查泄露文件来源与传播范围",
    }.get(category, "按资产安全基线处理并复测")


class LLMReviewer:
    """LLM 研判：批量调用 OpenAI 兼容接口；失败/超时降级规则版。"""

    def __init__(self):
        self.api_key = os.getenv("LLM_API_KEY", "")
        self.base_url = os.getenv("LLM_BASE_URL", "").rstrip("/") or "https://api.deepseek.com/v1"
        self.model = os.getenv("LLM_MODEL", "deepseek-chat")
        self.mode = "llm"
        self._fallback = RuleReviewer()

    def available(self) -> bool:
        return bool(self.api_key)

    def review(self, risks: list[dict]) -> list[dict]:
        try:
            return self._llm_review(risks)
        except Exception as e:
            out = self._fallback.review(risks)
            for r in out:
                r.setdefault("ai_explanation", {})["llm_error"] = str(e)[:200]
                r["ai_explanation"]["mode"] = "rule_fallback"
            return out

    def _llm_review(self, risks: list[dict]) -> list[dict]:
        import httpx
        batch = risks[:20]  # 单批最多 20 条，超出分批
        prompt = (
            "你是资深安全分析员。对以下巡检风险逐条研判，判断是真实风险(confirmed)、"
            "误报(false_positive)、还是证据不足待确认(unconfirmed)。\n"
            "要求：\n"
            "1. 输出合法 JSON 数组，每项对应一条输入，字段："
            "{\"index\": 序号, \"verdict\": \"confirmed|false_positive|unconfirmed\", "
            "\"confidence\": 0-1, \"explanation\": {\"evidence_summary\": \"证据归纳\", "
            "\"impact\": \"影响\", \"remediation\": \"可执行的修复建议\"}}\n"
            "2. 证据不足时必须判 unconfirmed，不要臆断；\n"
            "3. 修复建议要具体、可操作，针对 category 给出（如 vuln 建议升级/封堵，leak 建议下线并改密）。\n\n"
            f"风险列表：{json.dumps(batch, ensure_ascii=False)}"
        )
        resp = httpx.post(
            f"{self.base_url}/chat/completions",
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
                "temperature": 0.1,
            },
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=60,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        verdicts = json.loads(content)
        if isinstance(verdicts, dict):
            verdicts = verdicts.get("results", verdicts.get("items", []))
        by_index = {v.get("index"): v for v in verdicts}
        for i, r in enumerate(batch):
            v = by_index.get(i)
            if not v:
                continue
            r["status"] = v.get("verdict", "unconfirmed")
            exp = v.get("explanation", {})
            r["ai_explanation"] = {
                "evidence_summary": exp.get("evidence_summary", ""),
                "impact": exp.get("impact", ""),
                "remediation": exp.get("remediation", ""),
                "confidence": v.get("confidence"),
                "mode": "llm",
            }
        return batch


def create_reviewer():
    """工厂：配置 LLM_API_KEY 用 LLM 版，否则规则版。"""
    llm = LLMReviewer()
    if llm.available():
        return llm
    return RuleReviewer()
