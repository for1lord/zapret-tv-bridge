@echo off
setlocal
chcp 65001 >nul 2>&1

set "PROJECT_DIR=%~dp0"
set "PID_FILE=%PROJECT_DIR%tv_proxy.pid"
set "IP_FILE=%PROJECT_DIR%tv_proxy.ip"

echo [*] Остановка Zapret TV & Mobile Bridge...

if exist "%PID_FILE%" (
    for /f "usebackq delims=" %%p in ("%PID_FILE%") do (
        taskkill /F /T /PID %%p >nul 2>&1
        echo [+] Процесс с PID %%p остановлен.
    )
    del /f /q "%PID_FILE%" >nul 2>&1
)

:: Terminate any remaining orphan python processes running zapret_tv_bridge or tg_ws_proxy
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { ($_.CommandLine -like '*zapret_tv_bridge.py*' -or $_.CommandLine -like '*tg_ws_proxy*') } | ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {} }" >nul 2>&1

if exist "%IP_FILE%" del /f /q "%IP_FILE%" >nul 2>&1

echo [+] Все фоновые службы успешно остановлены.
timeout /t 2 /nobreak >nul
exit /b 0
