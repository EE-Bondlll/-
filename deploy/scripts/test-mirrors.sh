#!/usr/bin/env bash
# 测试国内 Docker 镜像加速器连通性
for m in docker.m.daocloud.io docker.mirrors.ustc.edu.cn mirror.ccs.tencentyun.com hub-mirror.c.163.com; do
  code=$(curl -4 -s -o /dev/null -w '%{http_code}' --max-time 10 "https://$m/v2/")
  echo "$m -> $code"
done
