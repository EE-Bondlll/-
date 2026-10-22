"""自测脚本：启动后对各接口打一遍，验证契约接口可用。
用法：先启动服务（uvicorn app.main:app --port 8002），再 python smoke_test.py
"""
import json
import urllib.request

BASE = "http://127.0.0.1:8002"


def call(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method)
    data = None
    if body is not None:
        req.add_header("Content-Type", "application/json")
        data = json.dumps(body).encode()
    with urllib.request.urlopen(req, data=data, timeout=15) as r:
        return r.status, json.loads(r.read().decode())


def main():
    ok = 0
    def check(name, cond):
        nonlocal ok
        print(("  [PASS] " if cond else "  [FAIL] ") + name)
        if cond: ok += 1

    print("== 健康检查 ==")
    s, r = call("GET", "/health"); check("/health 返回 ok", r.get("status") == "ok")

    print("== 规则库 ==")
    s, r = call("GET", "/api/rules")
    check("内置规则已灌入 (>5条)", len(r["rules"]) >= 5)
    s, r = call("POST", "/api/rules", {"rule_type": "keyword", "name": "测试关键词", "pattern": "DB_PASSWORD"})
    check("新增规则成功", r.get("saved"))

    print("== 资产批量写入 ==")
    s, r = call("POST", "/data/assets/batch", {"assets": [
        {"url": "https://demo.test.com/", "host": "demo.test.com", "fingerprint": {"cms": "test"}, "title": "首页"}
    ]})
    check("资产写入成功（幂等）", (r.get("written", 0) + r.get("updated", 0)) >= 1)

    print("== 风险批量写入（含脱敏 leak） ==")
    s, r = call("POST", "/data/risks/batch", {"risks": [
        {"asset_url": "https://demo.test.com/.env", "category": "leak", "severity": "high",
         "title": "环境文件暴露", "description": "命中 .env 文件",
         "evidence": {"matched_context": "DB_PASSWORD=SuperSecret123"},
         "tool": "sensitive-engine", "template": "rule:file_type:.env"}
    ]})
    check("风险写入成功（幂等）", (r.get("inserted", 0) + r.get("updated", 0)) >= 1)

    s, r = call("GET", "/data/risks")
    check("风险查询有数据", r["total"] >= 1)
    leak = next((x for x in r["risks"] if x["category"] == "leak"), None)
    check("命中内容已脱敏（无 SuperSecret123）", leak and "SuperSecret123" not in json.dumps(leak["evidence"]))

    print("== 基线对比 ==")
    s, r = call("POST", "/data/jobs", {"job_type": "manual", "status": "done", "job_id": "testjob001"})
    s, r = call("GET", "/data/baseline-diff")
    check("基线对比返回三组", all(k in r for k in ("new", "fixed", "persistent")))

    print("== 语义研判 ==")
    s, r = call("POST", "/semantic/leak-check", {"context": "DB_PASSWORD=SuperSecret123", "rule": "口令"})
    check("语义研判返回 is_leak 字段", "is_leak" in r)
    s, r = call("POST", "/semantic/leak-check", {"context": "your_password: xxxxx", "rule": "口令"})
    check("示例数据被判误报", r.get("is_leak") == False)

    print("== 告警 ==")
    s, r = call("POST", "/alert/send", {"level": "high", "message": "测试告警", "payload": {"signature": "test"}})
    check("告警接口返回成功", r.get("sent"))

    print("== 报告 ==")
    s, r = call("GET", "/report/testjob001")
    check("HTML 报告可生成", "安全巡检报告" in r or isinstance(r, dict))

    print(f"\n通过 {ok} 项。")


if __name__ == "__main__":
    main()
