@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1

set "PROJECT_DIR=%~dp0"
cd /d "%PROJECT_DIR%"

set "PID_FILE=%PROJECT_DIR%tv_proxy.pid"
set "IP_FILE=%PROJECT_DIR%tv_proxy.ip"
set "SECRET_FILE=%PROJECT_DIR%tg_secret.txt"
set "LOG_FILE=%PROJECT_DIR%tv_proxy.log"
set "STARTUP_FOLDER=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "SHORTCUT_PATH=%STARTUP_FOLDER%\Zapret_TV_Bridge.lnk"

:: Check Admin rights and auto-elevate
if /i "%~1"=="admin" (
    shift /1
    goto :main_init
)
net session >nul 2>&1
if not errorlevel 1 goto :main_init

:request_admin
title ZAPRET TV ^& MOBILE BRIDGE MANAGER
echo Requesting administrator privileges...
powershell -NoProfile -ExecutionPolicy Unrestricted -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\" admin %*\"' -Verb RunAs" 2>nul
if errorlevel 1 goto :main_init
exit /b

:main_init
title ZAPRET TV ^& MOBILE BRIDGE MANAGER v1.03

:: Locate executable or python environment
set "BRIDGE_EXE=%PROJECT_DIR%bin\ZapretTVBridge.exe"
if not exist "%BRIDGE_EXE%" set "BRIDGE_EXE=%PROJECT_DIR%ZapretTVBridge.exe"

set "USE_STANDALONE=0"
if exist "%BRIDGE_EXE%" (
    set "USE_STANDALONE=1"
) else (
    set "PY_BIN=python.exe"
    where pythonw.exe >nul 2>&1 && set "PY_BIN=pythonw.exe"
)

:: CLI Command dispatcher
set "CLI_CMD=%~1"
if /i "%CLI_CMD%"=="admin" set "CLI_CMD=%~2"

if /i "%CLI_CMD%"=="install" goto :opt_install_all
if /i "%CLI_CMD%"=="remove" goto :opt_remove_all
if /i "%CLI_CMD%"=="status" goto :opt_status
if /i "%CLI_CMD%"=="start" goto :opt_start_all
if /i "%CLI_CMD%"=="stop" goto :opt_remove_all

:menu_loop
call :refresh_status
cls

echo.
echo   ==================================================
echo   ZAPRET TV ^& MOBILE BRIDGE MANAGER v1.03
echo   ==================================================
echo   Служба Zapret:         !ZAPRET_STATUS_STR!
echo   Шлюз для ТВ/Мобильных: !STATUS_STR!
if "!IS_RUNNING!"=="1" (
    echo   Адрес шлюза:           http://!HOST_PORT!/
    echo   PAC URL:               http://!HOST_PORT!/proxy.pac
    echo   Smart TV:              IP !LOCAL_IP!  Port !LOCAL_PORT!
)
echo   Папка программы:       %PROJECT_DIR%
echo   --------------------------------------------------
echo.
echo   :: УПРАВЛЕНИЕ СЛУЖБАМИ
echo      1. Установить и запустить службы [Выбор стратегии Zapret]
echo      2. Остановить и удалить службы
echo      3. Проверить статус и адреса для подключения (ТВ / Смартфон)
echo.
echo   :: НАСТРОЙКИ
echo      4. Автозагрузка Windows              !STARTUP_STATUS!
echo      5. Открыть веб-панель в браузере
echo   --------------------------------------------------
echo      0. Выход
echo   --------------------------------------------------
echo.

set "CHOICE="
set /p CHOICE="   Выберите пункт [0-5]: "

if not defined CHOICE goto :menu_loop
if "%CHOICE%"=="1" goto :opt_install_all
if "%CHOICE%"=="2" goto :opt_remove_all
if "%CHOICE%"=="3" goto :opt_status
if "%CHOICE%"=="4" goto :opt_startup
if "%CHOICE%"=="5" goto :opt_dashboard
if "%CHOICE%"=="0" exit /b
goto :menu_loop

:: -----------------------------------------------------------------------------
:: SUBROUTINE: Refresh Status
:: -----------------------------------------------------------------------------
:refresh_status
set "IS_RUNNING=0"
set "CURRENT_PID="
set "STATUS_STR=[STOPPED]"
if exist "%PID_FILE%" (
    for /f "usebackq delims=" %%p in ("%PID_FILE%") do (
        tasklist /FI "PID eq %%p" 2>nul | findstr /i "%%p" >nul
        if not errorlevel 1 (
            set "IS_RUNNING=1"
            set "CURRENT_PID=%%p"
            set "STATUS_STR=[RUNNING - PID: %%p]"
        )
    )
)

set "ZAPRET_RUNNING=0"
set "ZAPRET_STRATEGY="
sc query zapret 2>nul | findstr /i "RUNNING" >nul
if not errorlevel 1 (
    set "ZAPRET_RUNNING=1"
) else (
    tasklist /FI "IMAGENAME eq winws.exe" 2>nul | findstr /i "winws.exe" >nul
    if not errorlevel 1 set "ZAPRET_RUNNING=1"
)

if "!ZAPRET_RUNNING!"=="1" (
    for /f "tokens=2*" %%A in ('reg query "HKLM\System\CurrentControlSet\Services\zapret" /v zapret-discord-youtube 2^>nul') do set "ZAPRET_STRATEGY=%%B"
    if defined ZAPRET_STRATEGY (
        set "ZAPRET_STATUS_STR=[RUNNING - !ZAPRET_STRATEGY!]"
    ) else (
        set "ZAPRET_STATUS_STR=[RUNNING]"
    )
) else (
    reg query "HKLM\System\CurrentControlSet\Services\zapret" >nul 2>&1
    if not errorlevel 1 (
        set "ZAPRET_STATUS_STR=[STOPPED]"
    ) else (
        set "ZAPRET_STATUS_STR=[NOT INSTALLED]"
    )
)

set "HOST_PORT=127.0.0.1:8080"
if exist "%IP_FILE%" (
    for /f "usebackq delims=" %%i in ("%IP_FILE%") do set "HOST_PORT=%%i"
)
for /f "tokens=1,2 delims=:" %%a in ("!HOST_PORT!") do (
    set "LOCAL_IP=%%a"
    set "LOCAL_PORT=%%b"
)

set "STARTUP_STATUS=[disabled]"
if exist "%SHORTCUT_PATH%" set "STARTUP_STATUS=[enabled]"
schtasks /query /tn "Zapret_TV_Bridge" >nul 2>&1
if not errorlevel 1 set "STARTUP_STATUS=[enabled]"
exit /b

:: -----------------------------------------------------------------------------
:: 1. INSTALL & START ALL SERVICES (PROMPTS FOR STRATEGY)
:: -----------------------------------------------------------------------------
:opt_install_all
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --install-all
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --install-all
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 2. STOP & REMOVE ALL SERVICES
:: -----------------------------------------------------------------------------
:opt_remove_all
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --remove-all
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --remove-all
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 3. CHECK STATUS & CONNECTION URLS
:: -----------------------------------------------------------------------------
:opt_status
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --status
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --status
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 4. WINDOWS STARTUP
:: -----------------------------------------------------------------------------
:opt_startup
cls
if "!STARTUP_STATUS!"=="[enabled]" (
    if "!USE_STANDALONE!"=="1" (
        "%BRIDGE_EXE%" --startup-disable
    ) else (
        python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --startup-disable
    )
) else (
    if "!USE_STANDALONE!"=="1" (
        "%BRIDGE_EXE%" --startup-enable
    ) else (
        python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --startup-enable
    )
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 5. OPEN DASHBOARD IN BROWSER
:: -----------------------------------------------------------------------------
:opt_dashboard
call :refresh_status
start "" "http://!HOST_PORT!/"
if defined CLI_CMD exit /b
goto :menu_loop

:: -----------------------------------------------------------------------------
:: START ALL SERVICES IN BACKGROUND
:: -----------------------------------------------------------------------------
:opt_start_all
cls
echo [*] Запуск всех служб в фоновом режиме...
sc start zapret >nul 2>&1
if "!USE_STANDALONE!"=="1" (
    powershell -NoProfile -Command "Start-Process '%BRIDGE_EXE%' -ArgumentList '--daemon' -WorkingDirectory '%PROJECT_DIR%' -WindowStyle Hidden"
) else (
    start /b "" "%PY_BIN%" "%PROJECT_DIR%zapret_tv_bridge.py" --daemon
)
if defined CLI_CMD exit /b
echo [+] Все службы успешно запущены.
timeout /t 2 >nul
goto :menu_loop
