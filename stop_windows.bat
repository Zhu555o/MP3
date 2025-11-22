@echo off
title MP3上传工具停止器

echo ========================================
echo    MP3上传工具停止脚本
echo ========================================
echo.

:: 关闭相关进程
echo [1/3] 关闭Flask应用...
taskkill /f /im python.exe /fi "WINDOWTITLE eq MP3 Uploader*" >nul 2>&1

echo [2/3] 关闭Celery Worker...
taskkill /f /im python.exe /fi "WINDOWTITLE eq Celery Worker*" >nul 2>&1

echo [3/3] 关闭Redis服务...
taskkill /f /im redis-server.exe >nul 2>&1

echo.
echo [完成] 所有服务已停止
timeout /t 2 >nul