#!/bin/bash

# === MP3上传工具 (含OSS) 停止脚本 ===

echo "========================================"
echo "   MP3上传工具 (含OSS) 停止脚本"
echo "========================================"
echo

# --- 1. 关闭Flask应用 ---
echo "[1/3] 关闭Flask应用..."
# 更精确地匹配在当前目录下运行的 server.py
pkill -f "python.*$(pwd).*/server\.py" > /dev/null 2>&1
# 如果上面的命令不够精确，可以回退到更通用的匹配（但可能误杀）
# pkill -f "python.*server\.py" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "    [信息] Flask应用关闭命令已发送"
else
    echo "    [信息] 未找到正在运行的Flask应用进程"
fi

# --- 2. 关闭Celery Worker ---
echo "[2/3] 关闭Celery Worker..."
# 匹配 celery worker 进程
pkill -f "celery.*worker" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "    [信息] Celery Worker关闭命令已发送"
else
    echo "    [信息] 未找到正在运行的Celery Worker进程"
fi

# --- 3. 关闭Redis服务 ---
echo "[3/3] 关闭Redis服务..."
# 尝试通过 PID 文件优雅关闭 (如果 redis-server 是以 --daemonize yes 启动并生成了 pid 文件)
# 假设 pid 文件在当前目录或 redis 默认位置
REDIS_PID_FILE="./redis.pid" # 根据你的 redis.conf 中 'pidfile' 项调整
if [ -f "$REDIS_PID_FILE" ]; then
    REDIS_PID=$(cat "$REDIS_PID_FILE")
    if kill -0 "$REDIS_PID" 2>/dev/null; then
        kill "$REDIS_PID"
        if [ $? -eq 0 ]; then
            echo "    [完成] Redis服务已通过PID文件停止 (PID: $REDIS_PID)"
            # 可选：删除 PID 文件
            # rm -f "$REDIS_PID_FILE"
        else
            echo "    [错误] 无法停止Redis服务 (PID: $REDIS_PID)"
        fi
    else
        echo "    [信息] PID文件存在但进程未运行 (PID: $REDIS_PID)"
        # 可选：删除陈旧的 PID 文件
        # rm -f "$REDIS_PID_FILE"
    fi
else
    # 如果没有 PID 文件，则使用 pkill 强制关闭
    # 注意：这可能会关闭系统中其他非相关的 redis-server 进程
    pkill redis-server > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "    [信息] Redis服务关闭命令已发送 (通过pkill)"
    else
        echo "    [信息] 未找到正在运行的Redis服务进程 (或pkill执行失败)"
    fi
fi

echo
echo "[完成] 停止脚本执行完毕"
echo "    请注意：某些进程可能需要几秒钟才能完全终止。"
sleep 2
