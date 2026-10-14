#!/usr/bin/env bash
# 配置 DaoCloud 镜像加速器并重启 docker
set -e
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{
  "registry-mirrors": ["https://docker.m.daocloud.io"]
}
EOF
cat /etc/docker/daemon.json
service docker restart
sleep 6
docker info --format 'mirrors={{json .RegistryConfig.Mirrors}}'
