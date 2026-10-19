# 部署与运行说明（交付形态）

## 一、架构与环境

| 项 | 说明 |
|---|---|
| 运行环境 | Windows + WSL2（Ubuntu 24.04）内 Docker Engine 29.9.0 + Compose v5.6.0 |
| 为什么不用 Docker Desktop | 本机网络阻断 desktop.docker.com（Docker Desktop 安装包），但 download.docker.com 与阿里云可达，故在 WSL 内装 Docker Engine，功能等价 |
| 容器 | postgres:16-alpine（5432）、redis:7-alpine（6379）、agent-core（8000）；detectors(8001)/sensitive-report(8002) 待 B/C 成员交付后补齐 |
| 数据 | PostgreSQL 首次启动自动执行 `contracts/schema.sql` 建表（已验证 6 张表） |

## 二、安装环境（已在本机完成，交付文档记录过程）

```bash
# 1. WSL 内一键安装 Docker（脚本已随仓库提交）
wsl -d Ubuntu -u root -- bash /mnt/d/<项目路径>/deploy/scripts/setup-docker-wsl.sh

# 2. 配置 DaoCloud 镜像加速器（Docker Hub 直连超时）
wsl -d Ubuntu -u root -- bash /mnt/d/<项目路径>/deploy/scripts/configure-docker-mirror.sh

# 3. 验证
wsl -d Ubuntu -u root -- docker version
wsl -d Ubuntu -u root -- docker compose version
```

关键配置说明：
- **强制 IPv4**：WSL 内 download.docker.com 仅解析 IPv6（CloudFront），而 WSL2 IPv6 路由不可用会导致下载卡死。已在 `/etc/apt/apt.conf.d/99force-ipv4` 配置 `Acquire::ForceIPv4 "true";`
- **镜像加速**：`/etc/docker/daemon.json` → `{"registry-mirrors":["https://docker.m.daocloud.io"]}`（仅 DaoCloud 在本网络可达）
- **systemd**：`/etc/wsl.conf` 已启用 `[boot] systemd=true`，docker 作为系统服务自动启动

## 三、WSL 空闲关闭问题的处理（重要）

**现象**：WSL 发行版在最后一次 wsl 命令结束后约 8 秒自动关闭，dockerd 随之停止、容器优雅退出。

**已采取的修复（双保险）**：
1. **常驻进程**：Windows 计划任务 `WSLInspectionKeepAlive`（登录时运行）→ `C:\Users\32024\keep-wsl-alive.bat` → 循环执行 `wsl.exe -d Ubuntu -u root --exec sleep 86400`（每轮保持 24 小时，wsl 退出后 5 秒自动重启，进程永不结束），保持发行版常驻。
2. **容器自愈**：docker-compose.yml 全部服务 `restart: unless-stopped`——即使发行版意外关闭后重新拉起，容器自动恢复。

**日常使用**：正常开机即可（计划任务登录自动保持）。若手动 `wsl --shutdown` 后，执行一次任意 wsl 命令即恢复全部服务。

## 四、启动 / 停止

```bash
# 启动（WSL 内）
cd /mnt/d/<项目路径>/deploy
docker compose up -d postgres redis agent-core    # B/C 完成后再加 detectors sensitive-report

# 查看状态
docker compose ps

# 停止（保留数据）
docker compose stop

# 彻底清理（删数据卷）
docker compose down -v
```

## 五、访问入口

| 服务 | 地址 |
|---|---|
| agent-core API 文档（Swagger） | http://localhost:8000/docs |
| 健康检查 | http://localhost:8000/health |
| PostgreSQL | localhost:5432（inspection / inspection_dev / inspection） |
| Redis | localhost:6379 |
| sensitive-report Dashboard | http://localhost:8002（待成员C） |

## 六、已完成的端到端验证（2026-10-15 容器化形态）

- 三个容器持续运行（postgres/redis healthy，agent-core Up）
- Windows 侧全链路：健康检查 → 配置录入（config_id）→ 发起巡检（job pending→done）→ 查询结果
- Mock 巡检产出：2 资产、9 原始风险、去重后 9、confirmed_high=3；风险含证据（evidence）、签名（signature）、三段式 AI 解释（证据/影响/修复建议）
- 表结构：assets / risks / baselines / jobs / audit_logs / sensitive_rules 全部建表成功

## 七、环境变量（deploy/.env，已从 .env.example 复制）

| 变量 | 默认 | 说明 |
|---|---|---|
| MOCK_MODE | 1 | 1=mock 检测器（B/C 未完成可演示）；0=真实服务 |
| LLM_API_KEY | 空 | 配置后 planner/reviewer 自动走 LLM；留空走规则版 |
| LLM_BASE_URL | https://api.deepseek.com/v1 | 恒脑/DeepSeek 兼容接口均可 |
| LLM_MODEL | deepseek-chat | |
| POSTGRES_* | inspection* | 与 compose 一致 |

## 八、待办（团队协作）

1. 成员B：`deploy/Dockerfile.detectors` + detectors 服务代码（8001）
2. 成员C：`deploy/Dockerfile.sensitive-report` + sensitive-report 服务代码（8002）
3. 补齐后 `docker compose up -d` 全量拉起；设 `MOCK_MODE=0` 联调
4. 配置 Git 远程仓库并推送（当前仅本地 master）
