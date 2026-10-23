# 成员B · 检测执行层验收反馈与修复清单

> 验收方：成员A ｜ 验收方式：仓库代码级核查 + 本机实测（HTTP 接口 + 检测逻辑）
> 仓库：https://github.com/479343012/secbot-detector
> 结论：**核心检测逻辑实现质量高，但有 1 个致命联调 bug + 2 个必改项，修完即可联调**

---

## 一、总览

| 项 | 结论 |
|---|---|
| 靶场搭建 | ✅ 7 站齐全（DVWA/WordPress+旧插件/挂马页/篡改页/备份文件/正常对照/HTTPS），含预期结果集 |
| 检测器实现 | ✅ discovery/vuln/tamper/malware/tls 逻辑真实完整，契约 Schema 对齐（14 字段） |
| signature 口径 | ✅ `sha256(url\|category\|title\|detail)`，与成员A/C 一致 |
| 自测体系 | ✅ pytest 5 个测试文件 + eval 评估脚本 + QPS 限速 |
| **HTTP 接口层** | ❌ **tamper/malware 路由重复定义，接口永远返回空** |
| **部署交付** | ❌ **docker-compose.yml 为空文件，无法一键部署** |
| **质量指标** | ⚠️ recall=1.0 ✅，但 **fp_rate=0.4（门槛 ≤0.1），自评 FAIL** |

---

## 二、必修问题

### P0-1：main.py 路由重复定义（致命，联调必挂）

**现象（实测确认）**：`POST /scan/tamper` 和 `POST /scan/malware` 返回 `{"job_id":"...","risks":[]}`——永远是空结果。

**原因**：`app/main.py` 中 `/scan/tamper` 和 `/scan/malware` 各被注册了**两次**：

```python
# —— 第一次注册：空实现（这个会生效！）——
@app.post("/scan/tamper", response_model=ScanResponse)
def scan_tamper(req: ScanRequest):
    return ScanResponse(job_id=str(uuid.uuid4()), risks=[])

@app.post("/scan/malware", response_model=ScanResponse)
def scan_malware(req: ScanRequest):
    return ScanResponse(job_id=str(uuid.uuid4()), risks=[])
```

FastAPI 按注册顺序匹配路由，**先注册的路由生效**，所以后面真实调用 `run_tamper`/`run_malware` 的实现永远不会被执行。

**为什么你的测试没发现**：pytest（tests/test_tamper.py 等）和 eval 脚本都是**直接调用 `run_tamper()` 函数**、绕过 HTTP 层；而成员A 联调走的是 HTTP 接口，所以一联调就拿到空结果。

**修复**：删除上面两段空实现（保留后面带 `run_tamper`/`run_malware` 的路由），确保每个路径只注册一次。

### P0-2：docker-compose.yml 为空文件（无法部署）

**现象**：仓库根目录 `docker-compose.yml` 内容为空；且检测器依赖 nuclei/subfinder/katana/gobuster/whatweb/wpscan/testssl 等二进制工具，仓库中没有安装方式说明。

**影响**：成员A 无法把 detectors 服务并入统一部署（`/opt/inspection` 的 compose 无法 build 起来）。

**修复要求**：
1. 提供可用的 `docker-compose.yml`：包含 `detectors` 服务（FastAPI 入口，端口 8001）+ 容器内工具链安装（可在 Dockerfile 里 `RUN` 安装 Go 工具，或用预装工具的基础镜像）
2. Dockerfile 中确保 `nuclei`（含模板目录）、`subfinder`、`katana`、`gobuster`、`whatweb`、`wpscan`、`testssl` 可执行，`/health` 返回的 `tools` 字段全部为 `true`
3. 服务需支持 `POST /scan/discovery|vuln|tamper|malware` + `GET /health`，请求体契约与任务书 2.2 一致

### P1-3：误报率超标（fp_rate=0.4，门槛 ≤0.1）

**证据**（`eval_report.json`）：`{"recall": 1.0, "fp_rate": 0.4, "tp": 6}`，4 条误报全部是：

```
target: http://localhost:8086  title: HTTP Missing Security Headers
```

**原因**：正常对照组（normal-page，8086）的 nginx 未配置安全头，被安全头检查器报了 4 条 `weak_config`（HSTS/CSP/X-Frame-Options/X-Content-Type-Options），而测试集把 8086 标注为 `clean`，于是算作误报。

**修复（二选一）**：
- 方案A：给 `normal-page` 靶站的 nginx 配置补上四个安全头（对照组"正常"应包含正常的安全头配置）
- 方案B：评估逻辑对 `clean` 目标豁免安全头检查（在 eval 脚本或 headers 适配器里跳过 clean 目标）

修复后重新跑 `python scripts/eval.py`，要求 `recall ≥ 0.9` 且 `fp_rate ≤ 0.1`，报告为 PASS。

---

## 三、建议修复（不阻塞联调，但影响体验）

### P2-4：仓库误提交 Windows 元数据文件

仓库里存在 `README_secbot-detector.md:Zone.Identifier`（Windows 下载文件附带的 NTFS 元数据被误提交）。

**影响**：**Windows 环境下 `git clone` 直接报错**（`invalid path`），成员A 和评审都无法正常拉取代码。

**修复**：
```bash
git rm --cached "README_secbot-detector.md:Zone.Identifier"
git commit -m "remove windows zone identifier file"
git push
```
同时在 `.gitignore` 中加入 `*:Zone.Identifier` 防止再次误提交。

---

## 四、其他观察（供参考，可不改）

1. `NucleiAdapter.run()` 用 `object.__setattr__(config, "timeout_sec", 1800)` 临时修改共享 config 的 timeout 到 30 分钟——config 对象是跨检测器共享的，虽然 try/finally 恢复了，但存在并发副作用风险，建议改为局部变量（如 `timeout = 1800` 只传给子进程）。
2. 8085（backup-files）在 expected_results.json 中标注"暂不计入指标"——如已实现相关探测，建议补回测试集。
3. 模板字段 `template` 在 tamper/malware 中为空字符串——契约允许，但建议统一填写特征名（如 `tamper:hash`），便于报告展示。

---

## 五、修复后验收标准（对照自查）

- [ ] `main.py` 每个路由只注册一次，`POST /scan/tamper`、`/scan/malware` 对靶站实测能返回非空 risks
- [ ] `docker-compose.yml` 可用，`docker compose up -d` 后 `/health` 返回 tools 全 true
- [ ] `python scripts/eval.py` 输出 PASS（recall ≥ 0.9 且 fp_rate ≤ 0.1）
- [ ] 仓库可在 Windows 上直接 `git clone`（无 Zone.Identifier 文件）
- [ ] 4 个接口请求/响应格式与任务书 2.2 契约一致

> 修复完成并推送后，告知成员A 即可进入联调（编排层 MOCK_MODE=0 接入 detectors:8001）。
