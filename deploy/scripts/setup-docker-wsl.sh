#!/usr/bin/env bash
# 在 WSL2 Ubuntu 中安装 Docker Engine + Docker Compose（阿里云源）
# 用法：wsl -d Ubuntu -- bash /mnt/d/作品/智能体运用/deploy/scripts/setup-docker-wsl.sh
set -euo pipefail

echo "==> 1. 配置阿里云 apt 源"
SRC=/etc/apt/sources.list.d/ubuntu.sources
if [ -f "$SRC" ]; then
  sed -i 's|http://archive.ubuntu.com/ubuntu|https://mirrors.aliyun.com/ubuntu|g; s|http://security.ubuntu.com/ubuntu|https://mirrors.aliyun.com/ubuntu|g' "$SRC"
fi
if [ -f /etc/apt/sources.list ]; then
  sed -i 's|http://archive.ubuntu.com/ubuntu|https://mirrors.aliyun.com/ubuntu|g; s|http://security.ubuntu.com/ubuntu|https://mirrors.aliyun.com/ubuntu|g' /etc/apt/sources.list
fi

echo "==> 2. apt update（容忍残留源索引错误，稍后覆盖）+ 强制 IPv4（WSL2 IPv6 不可用）"
echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4
apt-get update -qq || echo "(update warnings ignored)"

echo "==> 3. 添加 Docker GPG 与 docker-ce 源（官方 download.docker.com，强制 IPv4）"
apt-get install -y -qq ca-certificates curl gnupg lsb-release
install -m 0755 -d /etc/apt/keyrings
if [ ! -f /etc/apt/keyrings/docker-archive-keyring.gpg ]; then
  curl -4 -fsSL --max-time 30 https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker-archive-keyring.gpg \
  || curl -4 -fsSL --max-time 30 https://mirrors.aliyun.com/docker-ce/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker-archive-keyring.gpg
fi
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list

echo "==> 4. 重新 update 并安装 docker-ce + compose"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "==> 5. 启动 docker"
if ! service docker start; then
  echo "service 启动失败，尝试直接启动 dockerd"
  nohup dockerd > /var/log/dockerd.log 2>&1 &
  sleep 10
fi

echo "==> 6. 验证"
docker version --format 'client={{.Client.Version}} server={{.Server.Version}}'
docker compose version
echo "==> DONE"
