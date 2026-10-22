"""敏感内容脱敏：命中的真实值在 evidence / 报告 / 告警中一律打码，防止二次泄露。"""
import re

# 形如 key=value / key: value 的赋值片段：把 value 打码
_KV_RE = re.compile(r"((?:password|passwd|pwd|secret|token|apikey|api_key|access_key|"
                    r"private_key|db_password|database_url|connection_string)\s*[:=]\s*)"
                    r"['\"]?([^\s'\"&,<>{}$]+)", re.IGNORECASE)

# 常见凭据形态：AWS AKIA、私钥块、JWT、密钥串
_SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA****"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "-----BEGIN PRIVATE KEY*****"),
    (re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{5,}"), "JWT****"),
    (re.compile(r"(?i)(password|passwd|secret|token)\s*[:=]\s*\S+"), "****"),
]


def redact(text: str) -> str:
    """对一段文本做脱敏，保留前后文与键名，只打码值。"""
    if not text:
        return text
    text = _KV_RE.sub(lambda m: m.group(1) + "****", text)
    for pat, repl in _SECRET_PATTERNS:
        text = pat.sub(repl, text)
    # 身份证（18位）中间打码
    text = re.sub(r"\b(\d{6})\d{8}(\d{3}[0-9Xx])\b", r"\1********\2", text)
    # 手机号中间 4 位打码
    text = re.sub(r"\b1[3-9]\d{9}\b", lambda m: m.group(0)[:3] + "****" + m.group(0)[7:], text)
    return text
