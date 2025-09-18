#!/bin/bash

# === MP3上传工具 (含OSS) 启动脚本 ===

# --- 配置区域 (请根据实际情况修改) ---
# 设置脚本标题
echo -e "\033]0;MP3上传工具启动器\007"

# 设置阿里云 OSS 环境变量 (推荐方式)
# 将下面的 'your_actual_...' 替换为您的真实密钥和配置
# export OSS_ENABLED='true'
# export OSS_PROVIDER='aliyun_oss'
# export OSS_ACCESS_KEY_ID='your_actual_access_key_id'
# export OSS_ACCESS_KEY_SECRET='your_actual_access_key_secret'
# export OSS_BUCKET_NAME='your_actual_bucket_name'
# export OSS_ENDPOINT='oss-cn-hangzhou.aliyuncs.com' # 根据你的区域修改
# export OSS_REGION='cn-hangzhou' # 根据你的区域修改
# export OSS_CDN_DOMAIN='' # 如果有CDN，填写CDN域名，例如 https://your-cdn-domain.com

# 设置 Redis 连接信息 (如果使用密码)
# export CELERY_BROKER_URL='redis://:your_redis_password@127.0.0.1:6379/0'
# export CELERY_RESULT_BACKEND='redis://:your_redis_password@127.0.0.1:6379/0'

# --- 脚本执行区域 ---
echo "========================================"
echo "   MP3上传工具 (含OSS) 全自动启动脚本"
echo "========================================"
echo

# 检查是否为root用户运行
if [ "$EUID" -eq 0 ]; then
    echo "[信息] 正在以root权限运行"
else
    echo "[警告] 建议以root权限运行此脚本 (sudo ./start_linux.sh)"
fi

# 设置工作目录
cd "$(dirname "$0")"

# 检查Python是否安装
echo "[1/5] 检查Python环境..."
if ! command -v python3 &> /dev/null; then
    echo "[错误] 未找到Python3，请先安装Python 3.7+"
    exit 1
else
    PYTHON_VERSION=$(python3 --version)
    echo "[完成] $PYTHON_VERSION 已安装"
fi

# 检查并创建虚拟环境
echo "[2/5] 检查虚拟环境..."
if [ ! -d "venv" ]; then
    echo "[信息] 创建虚拟环境..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "[错误] 创建虚拟环境失败"
        exit 1
    fi
    echo "[完成] 虚拟环境创建成功"
else
    echo "[完成] 虚拟环境已存在"
fi

# 激活虚拟环境
echo "[3/5] 激活虚拟环境..."
source venv/bin/activate
if [ $? -ne 0 ]; then
    echo "[错误] 激活虚拟环境失败"
    exit 1
fi

# 安装依赖包 (包含OSS SDK)
echo "[4/5] 安装依赖包..."
pip install --upgrade pip > /dev/null 2>&1

# 尝试标准安装
pip install flask celery redis filetype oss2 > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[警告] 标准安装失败，尝试使用国内镜像源..."
    pip install flask celery redis filetype oss2 -i https://pypi.tuna.tsinghua.edu.cn/simple/ > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "[错误] 安装依赖包失败 (包括使用国内镜像)"
        deactivate
        exit 1
    fi
fi
echo "[完成] 依赖包 (含OSS SDK) 安装成功"

# 检查Redis服务
echo "[5/5] 检查Redis服务..."
if ! command -v redis-server &> /dev/null; then
    echo "[警告] 未找到Redis服务，异步上传功能将不可用"
    echo "[信息] 您可以继续使用同步和多线程上传功能"
    REDIS_AVAILABLE=false
else
    echo "[完成] Redis服务可用"
    REDIS_AVAILABLE=true
fi

# 启动服务
echo
echo "========================================"
echo "   启动MP3上传工具服务"
echo "========================================"
echo

# 启动Redis（如果可用且未运行）
if [ "$REDIS_AVAILABLE" = true ]; then
    # 简单检查Redis是否已在运行 (通过默认端口)
    if ! nc -z localhost 6379; then
        echo "[信息] 启动Redis服务..."
        redis-server > redis_server.log 2>&1 &
        REDIS_PID=$!
        sleep 3 # 等待Redis启动
        if ! kill -0 $REDIS_PID 2>/dev/null; then
            echo "[错误] Redis服务启动失败，请检查 redis_server.log"
            REDIS_AVAILABLE=false
        else
            echo "[完成] Redis服务已启动 (PID: $REDIS_PID)"
        fi
    else
        echo "[信息] Redis服务已在运行"
    fi
fi

# 启动Celery Worker（如果Redis可用）
CELERY_STARTED=false
if [ "$REDIS_AVAILABLE" = true ]; then
    echo "[信息] 启动Celery Worker..."
    # 尝试不同的终端模拟器来启动 Celery
    if command -v gnome-terminal &> /dev/null; then
        gnome-terminal --title="MP3 Uploader - Celery Worker" -- bash -c "cd '$(pwd)' && source venv/bin/activate && echo 'Celery Worker 启动中...' && celery -A celery_worker.celery_app worker --loglevel=info; read -p '按回车键关闭窗口...'" 2>/dev/null && CELERY_STARTED=true
    elif command -v konsole &> /dev/null; then
        konsole --title "MP3 Uploader - Celery Worker" -e bash -c "cd '$(pwd)' && source venv/bin/activate && echo 'Celery Worker 启动中...' && celery -A celery_worker.celery_app worker --loglevel=info; read -p '按回车键关闭窗口...'" 2>/dev/null && CELERY_STARTED=true
    elif command -v xterm &> /dev/null; then
        xterm -title "MP3 Uploader - Celery Worker" -e bash -c "cd '$(pwd)' && source venv/bin/activate && echo 'Celery Worker 启动中...' && celery -A celery_worker.celery_app worker --loglevel=info; read -p '按回车键关闭窗口...'" 2>/dev/null && CELERY_STARTED=true
    else
        # 如果没有图形终端，尝试在后台启动
        # 注意：后台启动的日志查看不如前台窗口方便
        nohup celery -A celery_worker.celery_app worker --loglevel=info > celery_worker_nohup.log 2>&1 &
        CELERY_PID=$!
        sleep 3
        if kill -0 $CELERY_PID 2>/dev/null; then
            echo "[完成] Celery Worker 已在后台启动 (PID: $CELERY_PID)"
            echo "[信息] 日志将输出到 celery_worker_nohup.log"
            CELERY_STARTED=true
        else
            echo "[错误] Celery Worker 启动失败"
            CELERY_STARTED=false
        fi
    fi

    if [ "$CELERY_STARTED" = true ]; then
        echo "[完成] Celery Worker 启动命令已发送"
    else
        echo "[警告] 无法启动 Celery Worker (可能没有图形终端)"
    fi
    sleep 3
fi

# 启动Flask应用
echo
echo "========================================"
echo "   启动Flask应用"
echo "========================================"
echo "[信息] 启动Flask服务器..."
sleep 2

# 在浏览器中打开应用 (延迟几秒，等服务器启动)
(
    sleep 5
    if command -v xdg-open &> /dev/null; then
        xdg-open http://localhost:5000 > /dev/null 2>&1
    elif command -v gnome-open &> /dev/null; then
        gnome-open http://localhost:5000 > /dev/null 2>&1
    fi
    echo "[信息] 尝试在浏览器中打开 http://localhost:5000"
) &

# 启动Flask服务器 (前台运行，方便查看日志)
python3 server.py

# 脚本结束时的清理工作 (可选，如果需要)
# deactivate # 取消激活虚拟环境
# if [ -n "$REDIS_PID" ] && kill -0 $REDIS_PID 2>/dev/null; then
#     echo "[信息] 停止 Redis 服务..."
#     kill $REDIS_PID
# fi
# if [ "$CELERY_STARTED" = true ] && [ -n "$CELERY_PID" ] && kill -0 $CELERY_PID 2>/dev/null; then
#     echo "[信息] 停止 Celery Worker..."
#     kill $CELERY_PID
# fi
