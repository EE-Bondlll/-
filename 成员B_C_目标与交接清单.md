# 成员B / 成员C：目标与交接清单（团队协作版）

> 用途：供成员A 对照验收 B/C 的交付物；B/C 按此自查进度。
> 依据：《成员A_智能体核心_任务书.md》《成员B_检测执行层_任务书.md》《成员C_敏感信息与数据报告_任务书.md》中的公共契约整理。
> 最后更新：2026-10-22

---

## 0. 三方总体配合（30 秒看懂）

```
恒脑平台智能体（门面，A）
        ↓ 对话触发
agent-core 编排引擎（大脑，A）  ← 调用 ↓
        ├── detectors 检测服务（手脚，B）：发现/漏洞/篡改/挂马 4 个检测器
        └── sensitive-report 数据服务（账本+门面，C）：
              敏感引擎 + 全项目数据库 + 报告 + Dashboard + 告警
```

- **A 依赖 B**：4 个检测器接口（discovery / vuln / tamper / malware）
- **A 依赖 C**：数据 API（写入/查询/基线对比）、告警 API、敏感检测 API、报告 API
- **B/C 互相无直接依赖**：B 输出检测 JSON → 由 A 编排后调 C 的数据 API 落库
- **协作铁律**：契约只增不改；任何修改当天同步另外两人并更新 contracts 目录

---

## 1. 成员B（检测执行层）要完成的目标

### 1.1 靶场与测试集（先行，所有自测的基础）
- [ ] 搭建 DVWA 靶机（漏洞样例：SQLi / XSS / 弱口令等）
- [ ] 搭建 WordPress 漏洞实例（低版本 + 已知漏洞插件，驱动指纹策略演示）
- [ ] 搭建挂马模拟页（恶意外链 + 加密混淆 JS + 隐藏 iframe）
- [ ] 搭建篡改模拟页（与基线不一致的页面内容，用于篡改检测验证）
- [ ] 维护靶场"预期结果集"（每个靶站标注应命中哪些风险 → 测试集标注基准）
- [ ] 泄露靶场样例集由成员C 负责（.env / 备份文件 / PII 页面）

### 1.2 资产发现链
- [ ] subfinder 子域枚举封装（输入主域 → 输出子域列表）
- [ ] httpx 存活探测封装（状态码、标题、Server 头）
- [ ] katana 页面/资源爬取封装（URL、静态资源、robots.txt）
- [ ] 目录与备份文件探测（.bak / .sql / .env / .git 等）
- [ ] 资产清单归一输出：URL + 指纹 + 页面哈希（符合资产对象格式）

### 1.3 指纹识别
- [ ] whatweb / wappalyzer 指纹识别封装（CMS / 中间件 / 框架 / 版本）
- [ ] 指纹结果归一 JSON 输出（写入 asset.fingerprint，供 A 的策略路由使用）

### 1.4 漏洞与弱配置检测
- [ ] nuclei 封装：按指纹过滤模板（cve / misconfig）、`-ndc` 非破坏模式、限速 `-rl 5`
- [ ] wpscan 封装（仅对 WordPress 资产启用）
- [ ] testssl 封装（TLS 版本、证书、弱套件检测）
- [ ] 安全头检查脚本（HSTS / CSP / X-Frame-Options 等缺失检测）
- [ ] 全部检测器输出统一 Schema（evidence + raw_output 齐全）

### 1.5 篡改检测
- [ ] 页面快照与内容哈希基线（首次巡检输出 baselines 所需数据）
- [ ] 增量对比：当前快照 vs 基线，输出差异证据（diff / 截图）
- [ ] 篡改风险记录输出（signature 稳定，保证复测后可消警）

### 1.6 挂马/恶意外链检测
- [ ] 外链提取与信誉库比对（黑名单域名 / URL 匹配）
- [ ] JS 混淆熵检测（高熵、加密混淆脚本标记，阈值约 5.5 bits/char）
- [ ] 可疑跳转 / 挖矿脚本 / 隐藏 iframe 特征检测
- [ ] 结果输出统一 Schema

### 1.7 质量与验收标准（B 自测）
- [ ] 靶场 5 个靶站一键启动，预期结果集齐全
- [ ] 对靶场逐个检测器自测，比对预期结果
- [ ] 自测统计：漏洞/挂马/篡改**召回率 ≥ 90%，误报 ≤ 10%**
- [ ] 并发与限速优化（QPS ≤ 5、timeout ≤ 30、只读非破坏）
- [ ] 第 4 周起与 A 接口联调、与 C 数据落库联调无报错
- [ ] 第 8 周交付：靶场环境 + 检测器代码 + 测试集 + 部署说明

---

## 2. 成员B → 成员A 交接内容（接口契约）

### 2.1 服务信息
- 服务名：`detectors`，端口 **8001**
- 技术栈：FastAPI（HTTP），可 docker 化

### 2.2 B 暴露的接口（A 的编排器逐个调用）

| 接口 | 作用 | 返回 |
|---|---|---|
| `POST /scan/discovery` | 资产发现 | `{"assets": [资产对象数组]}` |
| `POST /scan/vuln` | 漏洞 + 弱配置 | `{"job_id":"...", "risks":[...]}` |
| `POST /scan/tamper` | 篡改检测 | `{"job_id":"...", "risks":[...]}` |
| `POST /scan/malware` | 挂马 / 恶意外链 | `{"job_id":"...", "risks":[...]}` |
| `GET /health` | 健康检查 | 服务状态 |

请求体统一格式：

```json
{
  "assets": [
    {"url": "https://example.com", "fingerprint": {"cms": "wordpress", "version": "5.2.3", "server": "nginx/1.18"}}
  ],
  "config": {"rate_limit_qps": 5, "non_destructive": true, "timeout_sec": 30}
}
```

### 2.3 风险统一 Schema（B 所有检测器的输出标准，全项目唯一）

```json
{
  "asset_url": "https://example.com/login.php",
  "category": "vuln",
  "severity": "high",
  "title": "WordPress 5.2.3 存在 XXE 漏洞 (CVE-2019-9787)",
  "description": "命中 Nuclei 模板 xxe.yaml：请求响应出现 XXE 特征",
  "evidence": {
    "request_sample": "GET /wp-xxx HTTP/1.1 ...",
    "response_sample": "HTTP/1.1 200 OK ...",
    "screenshot_ref": "screenshots/2026-10-13/abc.png",
    "matched_context": "命中上下文片段"
  },
  "raw_output": "检测工具原始输出（JSON 字符串）",
  "tool": "nuclei",
  "template": "xxe.yaml",
  "first_seen": "2026-10-13T20:00:00+08:00",
  "last_seen": "2026-10-13T20:00:00+08:00",
  "status": "active",
  "signature": "sha256(url + category + title + detail)"
}
```

- `category` 取值：`vuln` | `weak_config` | `tamper` | `malware` | `leak` | `bad_link`（B 主要产出前四种 + bad_link）
- `severity` 取值：`critical` | `high` | `medium` | `low`
- `signature`：去重与复测消警的唯一键，**务必稳定生成**：`sha256(url + category + title + 关键细节)`
- **非破坏原则**：所有检测只读、不写入、不利用漏洞，禁用 exploit 模板

### 2.4 资产对象格式（discovery 输出）

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

### 2.5 A 验收 B 的清单（怎么测）
- [ ] `curl detectors:8001/health` 返回正常
- [ ] 对靶场发 `POST /scan/vuln`，返回 risks 全部含 signature 且 schema 字段齐全
- [ ] 同一条风险重复扫描，signature 稳定不变（去重依赖）
- [ ] 篡改模拟页改内容后，`/scan/tamper` 能检出并带新旧哈希证据
- [ ] 挂马模拟页被检出，正常页不误报

---

## 3. 成员C（敏感信息与数据报告）要完成的目标

### 3.1 敏感信息规则库
- [ ] 关键词规则管理 API（用户自定义关键词增删改、启停）
- [ ] 正则规则库（身份证、手机号、邮箱、API Key、私钥、数据库连接串等模式）
- [ ] 文件类型规则（.env / .sql / .bak / .git / 配置文件等）
- [ ] 样例文件上传与相似度比对机制（用户提供样例 → 指纹/相似匹配）
- [ ] 规则库版本管理（生效 / 停用、变更记录）

### 3.2 敏感信息检测引擎
- [ ] 页面 / 资源内容抓取与规则匹配引擎（命中 → 生成 leak 记录）
- [ ] gitleaks 封装（对下载的代码库 / 文件做密钥泄露检测）
- [ ] 命中上下文收集（前后文片段、来源 URL、抓取时间）
- [ ] LLM 语义研判层：判断真实泄露 vs 测试数据 / 示例代码（`POST /semantic/leak-check`）
- [ ] 自动脱敏展示（命中内容打码后写入 evidence，避免二次泄露）
- [ ] 输出统一 Schema 落库（category = leak）

### 3.3 数据层（全项目数据中枢，唯一数据入口）
- [ ] PostgreSQL 建表（assets / risks / baselines / jobs / audit_logs / sensitive_rules + 索引）
- [ ] 风险记录 CRUD API（供 A 编排与 Dashboard 查询）
- [ ] 资产批量写入 API
- [ ] 任务状态记录 API（jobs）
- [ ] 审计日志查询接口
- [ ] 风险分页查询（category / severity / status / scope 过滤）

### 3.4 基线对比
- [ ] 基线对比查询接口（新增 / 已修复 / 持续风险 三种视图）
- [ ] 口径：新增=本次有上次无；已修复=上次有本次无；持续=两次都有

### 3.5 报告导出
- [ ] 报告模板设计（概览、按资产 / 类别分组、风险明细表）
- [ ] 证据展示（响应片段、截图、命中上下文，全部脱敏）
- [ ] 影响与修复建议展示（三段式，读 risks.ai_explanation）
- [ ] PDF 导出（weasyprint / reportlab，中文不乱码）
- [ ] HTML 报告导出
- [ ] 历史报告归档与查询

### 3.6 Dashboard 可视化
- [ ] 风险概览页（总数、按级别 / 类别分布）
- [ ] 风险趋势图（数量随时间变化）
- [ ] Top 资产与 Top 风险类型排行
- [ ] 风险生命周期视图（新增 / 已修复 / 持续）
- [ ] 巡检任务状态页（jobs 历史、成功 / 失败）
- [ ] 全部图表由数据 API 驱动（ECharts）

### 3.7 告警通道
- [ ] 飞书机器人告警（webhook 封装）
- [ ] 邮件告警（SMTP）
- [ ] 通用 Webhook（供外部系统接入）
- [ ] 告警规则配置（级别阈值、去重、24h 频率限制）

### 3.8 质量与验收标准（C 自测）
- [ ] 泄露靶场样例集（.env / 备份文件 / PII 页面）搭建完成
- [ ] 敏感引擎对靶场自测：**召回率 ≥ 90%，误报 ≤ 10%，命中内容全部脱敏**
- [ ] 数据 API 全部路由可调用，signature 冲突处理正确
- [ ] 报告（PDF + HTML）用真实数据渲染通过，中文正常
- [ ] Dashboard 四页图表由真实数据驱动
- [ ] 飞书告警送达验证通过
- [ ] 第 8 周交付：敏感引擎 + 数据层 + 报告 + Dashboard + 泄露测试集 + 部署说明

---

## 4. 成员C → 成员A 交接内容（接口契约）

### 4.1 服务信息
- 服务名：`sensitive-report`，端口 **8002**
- 技术栈：FastAPI + SQLAlchemy + PostgreSQL

### 4.2 C 暴露的接口（A 编排调用）

**数据 / 告警 / 报告 API：**

| 接口 | 用途 |
|---|---|
| `POST /data/assets/batch` | 批量写入资产 |
| `POST /data/risks/batch` | 批量写入风险（signature 唯一约束，冲突更新 last_seen/status） |
| `PATCH /data/risks/{id}` | 更新状态 / 研判结果（status / ai_explanation） |
| `GET /data/risks?category=&severity=&status=&scope=` | 风险查询（分页） |
| `GET /data/baseline-diff?scope=...` | 基线对比（新增/已修复/持续三组） |
| `POST /data/jobs` | 记录任务状态 |
| `POST /alert/send` | 触发告警（level / message / payload） |
| `GET /report/{job_id}` | 获取报告 |
| `GET /report/{job_id}/export?format=pdf\|html` | 导出报告 |

**敏感信息检测 API：**

| 接口 | 用途 |
|---|---|
| `POST /scan/sensitive` | 敏感信息检测 `{"assets":[...], "config":{"rules":[...]}}` |
| `POST /semantic/leak-check` | LLM 语义泄露判断 `{"context":..., "rule":...}` → `{"is_leak":true/false, "reason":"...", "confidence":0-1}` |

**规则配置 API（A 的配置管理可联动调用）：**

| 接口 | 用途 |
|---|---|
| `GET/POST/PUT/DELETE /api/rules` | 关键词/正则/文件类型规则增删改查 |
| `POST /api/rules/sample` | 上传样例文件（返回 file_id / sha256） |

### 4.3 数据库表结构（C 建表，A 连接使用）

```sql
CREATE TABLE assets (
  id BIGSERIAL PRIMARY KEY, url TEXT UNIQUE NOT NULL, host TEXT NOT NULL,
  fingerprint JSONB DEFAULT '{}', status_code INT, page_hash TEXT, title TEXT,
  discovered_at TIMESTAMPTZ DEFAULT now(), last_seen TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE risks (
  id BIGSERIAL PRIMARY KEY, asset_url TEXT NOT NULL REFERENCES assets(url),
  category TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
  description TEXT, evidence JSONB DEFAULT '{}', raw_output TEXT,
  tool TEXT, template TEXT, signature TEXT UNIQUE NOT NULL,
  status TEXT DEFAULT 'active', ai_explanation JSONB DEFAULT '{}',
  first_seen TIMESTAMPTZ DEFAULT now(), last_seen TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_risks_asset ON risks(asset_url);
CREATE INDEX idx_risks_status ON risks(status);

CREATE TABLE baselines (
  id BIGSERIAL PRIMARY KEY, asset_url TEXT NOT NULL REFERENCES assets(url),
  page_hash TEXT NOT NULL, snapshot_ref TEXT,
  created_at TIMESTAMPTZ DEFAULT now(), is_current BOOLEAN DEFAULT true
);

CREATE TABLE jobs (
  id BIGSERIAL PRIMARY KEY, job_type TEXT NOT NULL, target_scope JSONB,
  status TEXT DEFAULT 'pending', started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ,
  triggered_by TEXT, report_ref TEXT
);

CREATE TABLE audit_logs (
  id BIGSERIAL PRIMARY KEY, operator TEXT NOT NULL, action TEXT NOT NULL,
  target TEXT, detail JSONB, created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE sensitive_rules (
  id BIGSERIAL PRIMARY KEY, rule_type TEXT NOT NULL,  -- keyword | regex | file_type | sample
  name TEXT NOT NULL, pattern TEXT, severity TEXT DEFAULT 'medium',
  enabled BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT now()
);
```

### 4.4 A 验收 C 的清单（怎么测）
- [ ] `curl sensitive-report:8002/health` 正常（如有）
- [ ] 批量写入 100 条风险成功，重复 signature 自动去重不报错
- [ ] `GET /data/baseline-diff` 构造两次数据能正确输出新增/已修复/持续三类
- [ ] `POST /scan/sensitive` 对泄露样例能检出 leak 且 evidence 已脱敏
- [ ] `/report/{job_id}/export?format=pdf` 中文正常
- [ ] `POST /alert/send` 飞书告警真实送达

---

## 5. 协作红线（三方必须遵守）

1. **契约只增不改**：任何接口/Schema/表结构变更，必须先同步另外两人，再更新 `contracts/` 目录
2. **signature 规则唯一**：`sha256(url + category + title + 关键细节)`，B 生成、A 去重、C 存储，三方口径必须一致
3. **脱敏统一**：敏感命中内容在 evidence/报告/告警中一律打码（如 `DB_PASSWORD=****`）
4. **合规硬要求**：QPS ≤ 5、timeout ≤ 30、只读非破坏、任何目标先过授权白名单、全程审计日志
5. **并行开发**：B/C 未就绪时 A 用 mock 开发（已完成）；A 不阻塞 B/C，B/C 不阻塞 A

---

## 6. 集成切换点（A 侧，B/C 就绪后执行）

```yaml
# deploy/.env 或 docker-compose 环境变量
MOCK_MODE=0
DETECTOR_BASE_URL=http://detectors:8001       # → 成员B
DATA_BASE_URL=http://sensitive-report:8002    # → 成员C
```

- 切换后**编排代码零改动**（clients.py 已按契约写好真实 HTTP 调用）
- 需要把 detectors / sensitive-report 两个服务加进 docker-compose.yml
- 切换后跑一遍端到端：配置 → 巡检 → 研判 → 基线 → 报告，对照靶场预期结果集核对

---

## 7. 当前进度与待确认项（A 侧记录）

| 项 | 状态 |
|---|---|
| agent-core 全部接口 + mock 编排 + 基线/复测/告警 | ✅ 完成并部署（124.70.212.93:8000） |
| 恒脑平台对话集成（agent_scan 单工具 + trace 防编造） | ✅ 完成（4 个 action 真调用闭环） |
| 测试站简易靶场（124.70.212.93:8080） | ✅ 已部署（demo 用） |
| 成员B 检测器服务（detectors:8001） | ⏳ 待确认（D:\作品\智能体运用\detectors\ 为空目录） |
| 成员C 数据/报告服务（sensitive-report:8002） | ⏳ 待确认（sensitive-report/ 为空目录） |
| B 的靶场 5 站 + 预期结果集（testbed/） | ⏳ 待确认（testbed/ 为空目录） |
| C 的泄露样例集 / Dashboard / 报告 | ⏳ 待确认 |

> 行动：向 B/C 确认各自服务的代码路径、部署状态、接口实现进度；就绪后由 A 牵头一键联调。
