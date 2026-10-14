#!/usr/bin/env bash
# 诊断 dockerd 启动时间与重启记录
ps -p "$(pgrep dockerd)" -o pid,lstart,cmd --no-headers
echo '---JOURNAL---'
journalctl -u docker --no-pager 2>&1 | grep -E 'Stopping|Stopped|Started|restart|SIGTERM|signal' | tail -12
