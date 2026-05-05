@echo off
REM Quick Start Script for Lingma OAuth Monitoring
REM 快速启动脚本 - 自动检测并运行监控

setlocal enabledelayedexpansion

echo.
echo ================================================================================
echo                    Lingma OAuth Login Monitor - Quick Start
echo ================================================================================
echo.

REM 检查 Python 和 Frida
echo [Step 1/5] Checking prerequisites...
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found. Please install Python 3.7+
    pause
    exit /b 1
)

frida --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Frida not found. Installing...
    pip install frida-tools
    if !errorlevel! neq 0 (
        echo [!] Failed to install Frida
        pause
        exit /b 1
    )
)
echo [+] Prerequisites OK

REM 检查 lingma.exe 进程
echo.
echo [Step 2/5] Checking Lingma process...
frida-ps | findstr /i "lingma.exe" >nul
if %errorlevel% neq 0 (
    echo [!] lingma.exe is not running
    echo.
    echo [*] Please start Lingma client first, then run this script again.
    echo [*] You can download Lingma from: https://lingma.alibabacloud.com/
    echo.
    pause
    exit /b 1
)
echo [+] lingma.exe is running

REM 显示进程信息
echo.
echo [Step 3/5] Process information:
for /f "tokens=*" %%i in ('frida-ps ^| findstr /i "lingma"') do echo     %%i

REM 选择监控模式
echo.
echo [Step 4/5] Select monitoring mode:
echo     1. Full OAuth Flow Monitor (Detailed logs, all function hooks)
echo     2. Token Auto-Extractor (Automatic token extraction, clean output)
echo     3. Both (Run two Frida instances)
echo.
set /p choice="Enter your choice (1/2/3) [default: 2]: "

if "%choice%"=="" set choice=2

echo.
echo [Step 5/5] Starting monitoring...

if "%choice%"=="1" (
    echo [*] Starting Full OAuth Flow Monitor...
    echo [*] Please trigger OAuth login in Lingma (click login button)
    echo ================================================================================
    echo.
    frida -n lingma.exe -l frida_oauth_monitor.js
) else if "%choice%"=="2" (
    echo [*] Starting Token Auto-Extractor...
    echo [*] Please trigger OAuth login in Lingma (click login button)
    echo ================================================================================
    echo.
    frida -n lingma.exe -l frida_token_extractor.js
) else if "%choice%"=="3" (
    echo [*] Starting both monitors...
    echo [*] Opening two terminal windows...
    echo.

    REM 启动第一个脚本
    start "Lingma OAuth Monitor - Full" cmd /k "frida -n lingma.exe -l frida_oauth_monitor.js"

    REM 等待 2 秒
    timeout /t 2 /nobreak >nul

    REM 启动第二个脚本
    start "Lingma OAuth Monitor - Token Extractor" cmd /k "frida -n lingma.exe -l frama_token_extractor.js"

    echo [+] Both monitors started in separate windows
    echo [*] Please trigger OAuth login in Lingma
    pause
) else (
    echo [!] Invalid choice. Using default (Token Auto-Extractor)
    echo [*] Please trigger OAuth login in Lingma (click login button)
    echo ================================================================================
    echo.
    frida -n lingma.exe -l frida_token_extractor.js
)

echo.
echo ================================================================================
echo [*] Monitoring ended
pause