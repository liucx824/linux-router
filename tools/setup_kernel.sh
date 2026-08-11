#!/bin/sh
# 关闭内核 IPv4 转发，让用户态路由器独占转发权（路由测试前提）。
# 用法：sudo sh tools/setup_kernel.sh
# 还原：sudo sysctl -w net.ipv4.ip_forward=1

echo "== closing kernel ip_forward (router runs in user space) =="
sysctl -w net.ipv4.ip_forward=0
sysctl net.ipv4.ip_forward

echo "== interfaces currently up (for reference) =="
ip -o addr show | awk '$2 != "lo" {print}'
