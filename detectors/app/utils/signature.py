import hashlib

def make_signature(url: str, category: str, title: str, detail: str) -> str:
    """
    契约：sha256(url + category + title + detail)
    detail 约定：漏洞/弱配置用命中的 template 名（如 xxe.yaml），
                篡改用 new_hash，挂马用命中的特征名（如 obfuscated_js）
    """
    raw = f"{url}|{category}|{title}|{detail}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()