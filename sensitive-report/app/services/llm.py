"""LLM 客户端（OpenAI 兼容），供语义泄露研判使用。无 API Key 时走规则兜底。"""
import json
import re

import httpx

from .. import config

PROMPT = """你是网站安全巡检的二级研判助手。下面是敏感信息检测引擎命中的一段上下文。
请判断它到底是不是"真实的敏感信息泄露"，还是测试数据 / 示例代码 / 公开占位符。

【命中上下文】
{context}

【命中规则】{rule}

【判定要求】
- 真实泄露（is_leak=true）：真实密钥、真实身份证/手机号、真实口令、生产环境配置。
- 误报（is_leak=false）：example.com / example.com.cn 示例、placeholder、
  测试账号 test/123456、文档里的示例代码、已公开的公开密钥、打码内容。
- 证据不足时倾向 is_leak=false。

只输出 JSON，不要任何多余文字：
{{"is_leak": true/false, "reason": "一句话理由", "confidence": 0.0-1.0}}
"""

# 规则兜底：明显的示例/测试特征
_PLACEHOLDER = re.compile(
    r"(example\.com|example\.org|placeholder|your[_-]?password|test@test|123456|"
    r"xxxx|\*{3,}|dummy|sample|lorem ipsum|your[_-]?api[_-]?key)", re.IGNORECASE)


def check_leak(context: str, rule: str) -> dict:
    """判断命中上下文是否为真实泄露。"""
    # 规则兜底：明显是示例/占位符直接判误报
    if _PLACEHOLDER.search(context):
        return {"is_leak": False,
                "reason": "上下文包含 example/placeholder/test 等示例特征，规则兜底判误报",
                "confidence": 0.9}

    if not config.LLM_API_KEY:
        return {"is_leak": True,
                "reason": "未配置 LLM_API_KEY，规则层未识别为示例，默认按真实泄露处理",
                "confidence": 0.6}

    try:
        resp = httpx.post(
            f"{config.LLM_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {config.LLM_API_KEY}"},
            json={
                "model": config.LLM_MODEL,
                "messages": [{"role": "user",
                              "content": PROMPT.format(context=context[:1500], rule=rule)}],
                "temperature": 0,
                "response_format": {"type": "json_object"},
            },
            timeout=20,
        )
        content = resp.json()["choices"][0]["message"]["content"]
        data = json.loads(content)
        return {"is_leak": bool(data.get("is_leak")),
                "reason": data.get("reason", ""),
                "confidence": float(data.get("confidence", 0.7))}
    except Exception as e:
        return {"is_leak": True,
                "reason": f"LLM 调用失败（{type(e).__name__}），保守按真实泄露处理",
                "confidence": 0.5}
