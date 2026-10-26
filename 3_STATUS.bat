@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1

set "PROJECT_DIR=%~dp0"
set "PID_FILE=%PROJECT_DIR%tv_proxy.pid"
set "IP_FILE=%PROJECT_DIR%tv_proxy.ip"
set "SECRET_FILE=%PROJECT_DIR%tg_secret.txt"

echo ======================================================================
echo           Zapret TV ^& Mobile Bridge -- Статус сервиса
echo ======================================================================
echo.

set "IS_RUNNING=0"
set "CURRENT_PID="

if exist "%PID_FILE%" (
    for /f "usebackq delims=" %%p in ("%PID_FILE%") do (
        tasklist /FI "PID eq %%p" 2>nul | findstr /i "%%p" >nul
        if not errorlevel 1 (
            set "IS_RUNNING=1"
            set "CURRENT_PID=%%p"
        )
    )
)

if "!IS_RUNNING!"=="1" (
    echo [ СТАТУС ]: АКТИВЕН (Работает в фоне, PID: !CURRENT_PID!)
) else (
    echo [ СТАТУС ]: ОСТАНОВЛЕН (Фоновый процесс не запущен)
    echo.
    echo Чтобы запустить мост в фоне, запустите 2_START.vbs
    echo.
    pause
    exit /b 0
)

:: Read Host and Port from tv_proxy.ip
set "HOST_PORT=127.0.0.1:8080"
if exist "%IP_FILE%" (
    for /f "usebackq delims=" %%i in ("%IP_FILE%") do set "HOST_PORT=%%i"
)

:: Split IP and Port
for /f "tokens=1,2 delims=:" %%a in ("!HOST_PORT!") do (
    set "LOCAL_IP=%%a"
    set "LOCAL_PORT=%%b"
)

:: Read Telegram Secret
set "TG_SECRET="
if exist "%SECRET_FILE%" (
    for /f "usebackq delims=" %%s in ("%SECRET_FILE%") do set "TG_SECRET=%%s"
)

echo.
echo ----------------------------------------------------------------------
echo  ПАРАМЕТРЫ ДЛЯ ПОДКЛЮЧЕНИЯ УСТРОЙСТВ:
echo ----------------------------------------------------------------------
echo.
echo  1. Веб-интерфейс и статус-страница:
echo     http://!HOST_PORT!/
echo.
echo  2. Автоконфигурация PAC (iOS / iPad / Mac / Windows):
echo     http://!HOST_PORT!/proxy.pac
echo.
echo  3. Smart TV (LG webOS / Android TV / Apple TV):
echo     IP-адрес: !LOCAL_IP!
echo     Порт:     !LOCAL_PORT!
echo.
if defined TG_SECRET (
echo  4. Telegram MTProto (1 клик):
echo     tg://proxy?server=!LOCAL_IP!^&port=1443^&secret=dd!TG_SECRET!
echo.
)
echo ======================================================================
echo.
set /p OPEN_BROWSER="Открыть веб-панель управления в браузере? (Y/N): "
if /i "!OPEN_BROWSER!"=="Y" (
    start http://!HOST_PORT!/
)

exit /b 0
