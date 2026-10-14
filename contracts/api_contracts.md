# 服务间接口约定（HTTP，内部网络）

## 1. 成员B 检测器服务（成员A 调用）

| 接口 | 请求体 | 返回 |
|---|---|---|
| `POST /scan/discovery` | 主域列表 + 配置 | `{"assets": [资产对象数组]}` |
| `POST /scan/vuln` | 资产清单 + 配置 | `{"job_id": "...", "risks": [风险Schema数组]}` |
| `POST /scan/tamper` | 资产清单 + 配置 | `{"job_id": "...", "risks": [...]}` |
| `POST /scan/malware` | 资产清单 + 配置 | `{"job_id": "...", "risks": [...]}` |
| `GET /health` | - | 服务状态 |

**统一请求体格式：**

```json
{
  "assets": [
    {
      "url": "https://example.com",
      "fingerprint": {"cms": "wordpress", "version": "5.2.3", "server": "nginx/1.18"}
    }
  ],
  "config": {"rate_limit_qps": 5, "non_destructive": true, "timeout_sec": 30}
}
```

**统一响应格式：** `{"job_id": "uuid", "risks": [...]}` 或 `{"assets": [...]}`

**资产对象格式（discovery 输出）：**

```json
{
  "url": "https://example.com/wp-login.php",
  "host": "example.com",
  "fingerprint": {"cms": "wordpress", "version": "5.2.3", "server": "nginx/1.18"},
  "status_code": 200,
  "page_hash": "sha256(页面内容哈希，供篡改检测用)",
  "title": "登录页面"
}
```

## 2. 成员C 数据 / 告警 / 报告服务（成员A 调用）

| 接口 | 用途 | 请求体 |
|---|---|---|
| `POST /data/assets/batch` | 批量写入资产 | `{"assets": [...]}` |
| `POST /data/risks/batch` | 批量写入风险 | `{"risks": [...]}` |
| `PATCH /data/risks/{id}` | 更新状态/研判 | `{"status": "...", "ai_explanation": {...}}` |
| `GET /data/risks?category=&severity=&status=&scope=` | 风险查询 | - |
| `GET /data/baseline-diff?scope=...` | 基线对比（新增/已修复/持续风险） | - |
| `POST /data/jobs` | 记录任务状态 | `{"job_type": "...", "status": "...", ...}` |
| `POST /alert/send` | 触发告警 | `{"level": "high", "message": "...", "payload": {...}}` |
| `GET /report/{job_id}` | 获取报告 | - |
| `GET /report/{job_id}/export?format=pdf|html` | 导出报告 | - |
| `POST /scan/sensitive` | 敏感信息检测 | `{"assets": [...], "config": {"rules": [...]}}` |
| `POST /semantic/leak-check` | LLM 语义泄露判断 | `{"context": "...", "rule": "..."}` → `{"is_leak": true, "reason": "..."}` |

## 3. 成员A 编排服务对外 API（供恒脑平台 / 前端 / 演示）

| 接口 | 用途 |
|---|---|
| `POST /api/config` | 录入授权域名、范围、周期、敏感信息定义 |
| `POST /api/jobs/start` | 发起一次巡检（手动） |
| `GET /api/jobs` | 任务状态查询 |
| `GET /api/risks?category=&severity=&status=` | 风险查询 |
| `POST /api/retest` | 对指定风险发起复测 |

## 4. 协作约定

- 契约只增不改；修改必须当天同步三人并更新本文件。
- 检测器默认 `rate_limit_qps ≤ 5`、`timeout_sec ≤ 30`、只读非破坏。
- 任何目标必须先过授权白名单校验。
