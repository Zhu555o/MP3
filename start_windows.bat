@echo off
title MP3上传工具启动器

:: 检查是否以管理员权限运行
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [信息] 正在以管理员权限运行
) else (
    echo [警告] 建议以管理员权限运行此脚本
    timeout /t 2 >nul
)

echo ========================================
echo    MP3上传工具全自动启动脚本
echo ========================================
echo.

:: 设置工作目录
cd /d "%~dp0"

:: 检查Python是否安装
echo [1/5] 检查Python环境...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [错误] 未找到Python，请先安装Python 3.7+
    pause
    exit /b 1
) else (
    for /f "tokens=*" %%i in ('python --version') do set PYTHON_VERSION=%%i
    echo [完成] %PYTHON_VERSION% 已安装
)

:: 检查并创建虚拟环境
echo [2/5] 检查虚拟环境...
if not exist "venv" (
    echo [信息] 创建虚拟环境...
    python -m venv venv
    if %errorLevel% neq 0 (
        echo [错误] 创建虚拟环境失败
        pause
        exit /b 1
    )
    echo [完成] 虚拟环境创建成功
) else (
    echo [完成] 虚拟环境已存在
)

:: 激活虚拟环境
echo [3/5] 激活虚拟环境...
call venv\Scripts\activate.bat
if %errorLevel% neq 0 (
    echo [错误] 激活虚拟环境失败
    pause
    exit /b 1
)

:: 安装依赖包
echo [4/5] 安装依赖包...
pip install --upgrade pip >nul 2>&1
pip install flask celery redis mutagen >nul 2>&1
if %errorLevel% neq 0 (
    echo [警告] 标准安装失败，尝试使用国内镜像源...
    pip install flask celery redis mutagen -i https://pypi.tuna.tsinghua.edu.cn/simple/ >nul 2>&1
    if %errorLevel% neq 0 (
        echo [错误] 安装依赖包失败
        pause
        exit /b 1
    )
)
echo [完成] 依赖包安装成功

:: 检查Redis服务
echo [5/5] 检查Redis服务...
redis-server --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [警告] 未找到Redis服务，异步功能将不可用
    echo [信息] 您可以继续使用同步上传功能
    set REDIS_AVAILABLE=false
) else (
    echo [完成] Redis服务可用
    set REDIS_AVAILABLE=true
)

:: 启动服务
echo.
echo ========================================
echo    启动MP3上传工具服务
echo ========================================
echo.

:: 启动Redis（如果可用）
if "%REDIS_AVAILABLE%"=="true" (
    echo [信息] 启动Redis服务...
    start "Redis Server" /min redis-server
    timeout /t 3 >nul
)

:: 启动Celery Worker（如果Redis可用）
if "%REDIS_AVAILABLE%"=="true" (
    echo [信息] 启动Celery Worker...
    start "Celery Worker" cmd /c "venv\Scripts\activate.bat && celery -A celery_worker.celery_app worker --loglevel=info ^|^| echo Celery启动失败 && pause"
    timeout /t 3 >nul
)

:: 启动Flask应用
echo [信息] 启动Flask应用...
timeout /t 2 >nul
start "MP3 Uploader" http://localhost:5000
python server.py

:: 结束脚本
echo.
echo [信息] 服务已启动，请按任意键退出...
pause >nul