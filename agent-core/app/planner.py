"""巡检计划生成模块（任务书 4.2）。

- 规则版（RulePlanner）：确定性生成，无需 API Key，先跑通闭环。
- LLM 版（LLMPlanner）：接入恒脑/DeepSeek 等 OpenAI 兼容接口生成计划；
  未配置 LLM_API_KEY 或调用失败时自动降级规则版（mode=rule_fallback）。
- 指纹 → 检测策略路由（route_strategy）：按资产指纹动态选择检测器与模板。
"""
import hashlib
import json
import os
from datetime import datetime, timezone

# 计划步骤统一携带容错参数（超时/重试/失败跳过），编排器按此执行
_STEP_FALLOUT = {"timeout_sec": 30, "retries": 1, "skip_on_fail": True}


def route_strategy(fingerprint: dict | None) -> list[dict]:
    """指纹 → 检测策略路由（规则版）。输入资产指纹，输出应执行的检测步骤。"""
    fp = fingerprint or {}
    cms = (fp.get("cms") or "").lower()
    server = (fp.get("server") or "").lower()
    framework = (fp.get("framework") or "").lower()

    steps: list[dict] = []
    if "wordpress" in cms or "wp" in cms:
        steps.append({"endpoint": "/scan/vuln", "profile": "wordpress",
                      "note": "WPScan + nuclei wordpress 模板（按指纹定向）"})
    elif framework:
        steps.append({"endpoint": "/scan/vuln", "profile": framework,
                      "note": f"nuclei {framework} 框架模板"})
    else:
        steps.append({"endpoint": "/scan/vuln", "profile": "general",
                      "note": "nuclei 通用 cve/misconfig 模板"})
    if any(k in server for k in ("nginx", "apache", "iis", "tomcat")):
        steps.append({"endpoint": "/scan/vuln", "profile": "weak_config",
                      "note": "testssl + 安全头检查（弱配置）"})
    return steps


def build_plan(cfg: dict, mode: str = "rule") -> dict:
    """读取配置，生成端到端巡检计划 JSON（规则版）。"""
    domains = cfg.get("domains", [])
    plan_id = hashlib.sha256(",".join(sorted(domains)).encode()).hexdigest()[:12]
    steps = [
        {"stage": "discovery", "service": "detectors", "endpoint": "/scan/discovery",
         "targets": domains, "note": "子域枚举→存活探测→页面爬取→指纹", **_STEP_FALLOUT},
        {"stage": "policy_routing", "service": "agent-core", "mode": mode,
         "note": "按每个资产的指纹调用 route_strategy 动态选择检测策略", **_STEP_FALLOUT},
        {"stage": "detect", "service": "detectors", "endpoint": "/scan/vuln",
         "profile": "auto", "note": "漏洞/弱配置（按指纹路由后执行）", **_STEP_FALLOUT},
        {"stage": "detect", "service": "detectors", "endpoint": "/scan/tamper",
         "note": "篡改检测（页面哈希 vs 基线）", **_STEP_FALLOUT},
        {"stage": "detect", "service": "detectors", "endpoint": "/scan/malware",
         "note": "挂马/恶意外链检测（信誉库+JS 熵）", **_STEP_FALLOUT},
        {"stage": "detect", "service": "sensitive-report", "endpoint": "/scan/sensitive",
         "rules": cfg.get("sensitive_rules", []),
         "note": "敏感信息检测（关键词/正则/文件类型/样例）", **_STEP_FALLOUT},
        {"stage": "aggregate", "service": "agent-core",
         "note": "统一 Schema 聚合 + signature 去重 + 定级", **_STEP_FALLOUT},
        {"stage": "review", "service": "agent-core",
         "note": "LLM 误报研判 + 证据→影响→修复建议三段式解释", **_STEP_FALLOUT},
        {"stage": "baseline", "service": "sensitive-report", "endpoint": "/data/baseline-diff",
         "note": "基线对比：新增 / 已修复 / 持续风险", **_STEP_FALLOUT},
        {"stage": "alert_report", "service": "sensitive-report",
         "endpoint": "/alert/send + /report", "note": "告警 + 报告导出", **_STEP_FALLOUT},
    ]
    return {
        "plan_id": plan_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "domains": domains,
        "scope": cfg.get("scope", "full"),
        "cron": cfg.get("cron"),
        "sensitive_rules": cfg.get("sensitive_rules", []),
        "steps": steps,
    }


class RulePlanner:
    def build_plan(self, cfg: dict) -> dict:
        return build_plan(cfg, mode="rule")


_LLM_PLAN_TEMPLATE = {
    "plan_id": "由配置生成",
    "generated_at": "ISO8601",
    "mode": "llm",
    "domains": ["example.com"],
    "scope": "full",
    "cron": "0 2 * * *",
    "steps": [
        {"stage": "discovery", "service": "detectors", "endpoint": "/scan/discovery",
         "targets": ["example.com"], "note": "资产与页面发现"},
        {"stage": "detect", "service": "detectors", "endpoint": "/scan/vuln",
         "profile": "general", "note": "漏洞检测"},
        {"stage": "detect", "service": "sensitive-report", "endpoint": "/scan/sensitive",
         "rules": [], "note": "敏感信息检测"}
    ]
}


class LLMPlanner:
    """LLM 规划：调用 OpenAI 兼容接口（恒脑/DeepSeek）生成计划。

    环境变量：LLM_API_KEY（必填启用）、LLM_BASE_URL、LLM_MODEL。
    调用失败（超时/解析失败）自动降级规则版，不影响巡检可用性。
    """

    def __init__(self):
        self.api_key = os.getenv("LLM_API_KEY", "")
        self.base_url = os.getenv("LLM_BASE_URL", "").rstrip("/") or "https://api.deepseek.com/v1"
        self.model = os.getenv("LLM_MODEL", "deepseek-chat")

    def available(self) -> bool:
        return bool(self.api_key)

    def build_plan(self, cfg: dict) -> dict:
        try:
            return self._llm_plan(cfg)
        except Exception as e:
            plan = build_plan(cfg, mode="rule_fallback")
            plan["llm_error"] = str(e)[:200]
            return plan

    def _llm_plan(self, cfg: dict) -> dict:
        import httpx
        prompt = (
            "你是网站安全巡检智能体的规划引擎。根据下面的巡检配置，生成一份巡检计划 JSON。\n"
            "要求：\n"
            "1. 必须输出合法 JSON，不要输出其他文字；\n"
            "2. steps 是端到端步骤数组，至少包含：资产发现、漏洞/弱配置检测、篡改检测、"
            "挂马/外链检测、敏感信息检测、结果聚合研判、基线对比、告警报告；\n"
            "3. service 取值只能为 detectors / sensitive-report / agent-core；\n"
            "4. 结合敏感信息规则（关键词/正则/文件类型）细化 sensitive 步骤的 rules 字段；\n"
            "5. 每个步骤需含 timeout_sec(30)、retries(1)、skip_on_fail(true)。\n\n"
            f"巡检配置：{json.dumps(cfg, ensure_ascii=False)}\n\n"
            f"输出结构参考：{json.dumps(_LLM_PLAN_TEMPLATE, ensure_ascii=False)}"
        )
        resp = httpx.post(
            f"{self.base_url}/chat/completions",
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
                "temperature": 0.2,
            },
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=60,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        plan = json.loads(content)  # 非 JSON 会抛异常 → 外层降级
        plan["mode"] = "llm"
        plan["generated_at"] = datetime.now(timezone.utc).isoformat()
        plan.setdefault("steps", [])
        return plan


def create_planner():
    """工厂：配置了 LLM_API_KEY 用 LLM 版，否则规则版。"""
    llm = LLMPlanner()
    if llm.available():
        return llm
    return RulePlanner()
