@echo off
REM Lingma OAuth Monitor - Frida Injection Script
REM Author: Security Testing Lab
REM Date: 2026-05-01

echo ================================================================================
echo [*] Lingma OAuth Login Flow Monitor
echo [*] Target: lingma.exe (Windows x64)
echo ================================================================================
echo.

REM 检查 Frida 是否安装
echo [1/4] Checking Frida installation...
frida --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Frida is not installed or not in PATH
    echo [*] Installing Frida...
    pip install frida-tools
    if %errorlevel% neq 0 (
        echo [!] Failed to install Frida. Please install manually:
        echo     pip install frida-tools
        pause
        exit /b 1
    )
)
echo [+] Frida is installed

REM 检查 lingma.exe 是否运行
echo.
echo [2/4] Checking if lingma.exe is running...
frida-ps | findstr /i "lingma.exe" >nul
if %errorlevel% neq 0 (
    echo [!] lingma.exe is not running
    echo [*] Please start Lingma first, then run this script again
    pause
    exit /b 1
)
echo [+] lingma.exe is running

REM 列出进程详情
echo.
echo [3/4] Process details:
frida-ps | findstr /i "lingma"

REM 注入 Frida 脚本
echo.
echo [4/4] Injecting Frida script...
echo [*] Starting OAuth flow monitoring...
echo [*] Please trigger OAuth login in Lingma (click login button)
echo ================================================================================
echo.

frida -n lingma.exe -l frida_oauth_monitor.js

echo.
echo ================================================================================
echo [*] Monitoring ended
pause