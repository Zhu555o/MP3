#!/bin/bash

echo "========================================"
echo "   Redis安装脚本 (Ubuntu/Debian)"
echo "========================================"
echo

# 检查系统类型
if [ -f /etc/debian_version ]; then
    echo "[信息] 检测到Debian/Ubuntu系统"
    sudo apt update
    sudo apt install -y redis-server
elif [ -f /etc/redhat-release ]; then
    echo "[信息] 检测到RedHat/CentOS系统"
    sudo yum install -y redis
    sudo systemctl enable redis
    sudo systemctl start redis
elif [ -f /etc/arch-release ]; then
    echo "[信息] 检测到Arch Linux系统"
    sudo pacman -S redis
    sudo systemctl enable redis
    sudo systemctl start redis
else
    echo "[错误] 不支持的操作系统，请手动安装Redis"
    exit 1
fi

echo
echo "[完成] Redis安装成功"
echo "[信息] 请运行 start_linux.sh 启动服务"