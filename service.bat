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
title ZAPRET TV ^& MOBILE BRIDGE MANAGER v1.01

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

if /i "%CLI_CMD%"=="install" goto :opt_install_zapret
if /i "%CLI_CMD%"=="remove" goto :opt_remove_zapret
if /i "%CLI_CMD%"=="start" (
    call :refresh_status
    goto :opt_start
)
if /i "%CLI_CMD%"=="stop" (
    call :refresh_status
    goto :opt_stop
)
if /i "%CLI_CMD%"=="restart" (
    call :refresh_status
    goto :opt_restart
)
if /i "%CLI_CMD%"=="status" (
    goto :opt_status
)
if /i "%CLI_CMD%"=="optimize" goto :opt_optimize
if /i "%CLI_CMD%"=="fix-proxy" goto :opt_fix_proxy
if /i "%CLI_CMD%"=="firewall" goto :opt_firewall
if /i "%CLI_CMD%"=="test" goto :opt_test

:menu_loop
call :refresh_status
cls

echo.
echo   ==================================================
echo   ZAPRET TV ^& MOBILE BRIDGE MANAGER v1.01
echo   ==================================================
echo   Zapret Service: !ZAPRET_STATUS_STR!
if "!IS_RUNNING!"=="1" (
    echo   Bridge Status:  !STATUS_STR!
    echo   Address:        http://!HOST_PORT!/
    echo   PAC URL:        http://!HOST_PORT!/proxy.pac
    echo   Smart TV:       IP !LOCAL_IP!  Port !LOCAL_PORT!
) else (
    echo   Bridge Status:  !STATUS_STR!
    echo   Address:        Не активен
)
echo   Directory:      %PROJECT_DIR%
echo   --------------------------------------------------
echo.
echo   :: SERVICE
echo      1. Install Zapret Service [Choose Strategy]
echo      2. Remove Zapret Service [Stop ^& Delete]
echo      3. Start Bridge [Background]
echo      4. Stop Bridge
echo      5. Restart Bridge
echo      6. Check Status ^& Connection URLs
echo.
echo   :: SETTINGS ^& OPTIMIZATION
echo      7. Windows Startup              !STARTUP_STATUS!
echo      8. Optimize Windows 11 Network [Fix Speed, RSC, QUIC, Kyber, IPv6]
echo      9. Fix Windows Proxy [Protect Antigravity / AG Configurator]
echo      10. Generate New Telegram MTProto Key
echo      11. Open Domain Routing Lists Folder
echo.
echo   :: TOOLS ^& LOGS
echo      12. Open Web Dashboard in Browser
echo      13. View Live Logs [tv_proxy.log]
echo      14. Run Diagnostics ^& DoH Latency Test
echo.
echo   --------------------------------------------------
echo      0. Exit
echo   --------------------------------------------------
echo.

set "CHOICE="
set /p CHOICE="   Select option [0-14]: "

if not defined CHOICE goto :menu_loop
if "%CHOICE%"=="1" goto :opt_install_zapret
if "%CHOICE%"=="2" goto :opt_remove_zapret
if "%CHOICE%"=="3" goto :opt_start
if "%CHOICE%"=="4" goto :opt_stop
if "%CHOICE%"=="5" goto :opt_restart
if "%CHOICE%"=="6" goto :opt_status
if "%CHOICE%"=="7" goto :opt_startup
if "%CHOICE%"=="8" goto :opt_optimize
if "%CHOICE%"=="9" goto :opt_fix_proxy
if "%CHOICE%"=="10" goto :opt_tg_secret
if "%CHOICE%"=="11" goto :opt_lists
if "%CHOICE%"=="12" goto :opt_dashboard
if "%CHOICE%"=="13" goto :opt_logs
if "%CHOICE%"=="14" goto :opt_test
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
sc query zapret 2>nul | findstr /i "STATE" | findstr /i "RUNNING" >nul
if not errorlevel 1 (
    set "ZAPRET_RUNNING=1"
    for /f "tokens=2*" %%A in ('reg query "HKLM\System\CurrentControlSet\Services\zapret" /v zapret-discord-youtube 2^>nul') do set "ZAPRET_STRATEGY=%%B"
)

if "!ZAPRET_RUNNING!"=="1" (
    if defined ZAPRET_STRATEGY (
        set "ZAPRET_STATUS_STR=[RUNNING - !ZAPRET_STRATEGY!]"
    ) else (
        set "ZAPRET_STATUS_STR=[RUNNING]"
    )
) else (
    sc query zapret 2>nul | findstr /i "zapret" >nul
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
exit /b

:: -----------------------------------------------------------------------------
:: 1. INSTALL ZAPRET SERVICE (CHOOSE STRATEGY)
:: -----------------------------------------------------------------------------
:opt_install_zapret
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --install-strategy
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --install-strategy
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 2. REMOVE ZAPRET SERVICE
:: -----------------------------------------------------------------------------
:opt_remove_zapret
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --remove-service
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --remove-service
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 3. START BRIDGE
:: -----------------------------------------------------------------------------
:opt_start
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --start
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --start
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 4. STOP BRIDGE
:: -----------------------------------------------------------------------------
:opt_stop
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --stop
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --stop
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 5. RESTART BRIDGE
:: -----------------------------------------------------------------------------
:opt_restart
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --restart
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --restart
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 6. STATUS
:: -----------------------------------------------------------------------------
:opt_status
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --status
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --status
)
if defined CLI_CMD exit /b
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 7. STARTUP TOGGLE
:: -----------------------------------------------------------------------------
:opt_startup
cls
echo ======================================================================
echo    Zapret TV ^& Mobile Bridge -- Автозагрузка Windows
echo ======================================================================
echo.
if exist "%SHORTCUT_PATH%" (
    echo [+] Мост УЖЕ добавлен в автозагрузку Windows.
    echo.
    set /p DEL_CHOICE="   Удалить из автозагрузки? (Y/N): "
    if /i "!DEL_CHOICE!"=="Y" (
        if "!USE_STANDALONE!"=="1" (
            "%BRIDGE_EXE%" --startup-disable
        ) else (
            python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --startup-disable
        )
    )
) else (
    echo [*] Мост пока НЕ добавлен в автозагрузку.
    echo.
    set /p ADD_CHOICE="   Добавить тихий фоновый запуск в автозагрузку? (Y/N): "
    if /i "!ADD_CHOICE!"=="Y" (
        if "!USE_STANDALONE!"=="1" (
            "%BRIDGE_EXE%" --startup-enable
        ) else (
            python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --startup-enable
        )
    )
)
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 8. OPTIMIZE WINDOWS 11 NETWORK (RSC, QUIC, KYBER, IPV6)
:: -----------------------------------------------------------------------------
:opt_optimize
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --optimize-network
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --optimize-network
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 9. FIX WINDOWS PROXY (PROTECT ANTIGRAVITY / AG CONFIGURATOR)
:: -----------------------------------------------------------------------------
:opt_fix_proxy
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --fix-proxy
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --fix-proxy
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 9. TG SECRET
:: -----------------------------------------------------------------------------
:opt_tg_secret
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --secret
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --secret
)
if defined CLI_CMD exit /b
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 10. DOMAIN LISTS
:: -----------------------------------------------------------------------------
:opt_lists
cls
echo.
echo [*] Открытие папки со списками доменов...
start explorer.exe "%PROJECT_DIR%lists"
ping 127.0.0.1 -n 2 >nul
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 11. DASHBOARD
:: -----------------------------------------------------------------------------
:opt_dashboard
start http://!HOST_PORT!/
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 13. LIVE LOGS
:: -----------------------------------------------------------------------------
:opt_logs
cls
echo ======================================================================
echo    Мониторинг журнала tv_proxy.log в реальном времени
echo    Нажмите Ctrl+C для выхода обратно в меню
echo ======================================================================
echo.
if exist "%LOG_FILE%" (
    powershell -NoProfile -Command "Get-Content -Wait -Tail 30 '%LOG_FILE%'"
) else (
    echo [i] Файл журнала tv_proxy.log пока пуст. Запустите мост.
    echo.
    pause
)
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 13. DIAGNOSTICS & TESTS
:: -----------------------------------------------------------------------------
:opt_test
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --test
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --test
)
if defined CLI_CMD exit /b
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: FIREWALL DIRECT CLI
:: -----------------------------------------------------------------------------
:opt_firewall
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --firewall
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --firewall
)
if defined CLI_CMD exit /b
pause
goto :menu_loop