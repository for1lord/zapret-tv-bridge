@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1

set "PROJECT_DIR=%~dp0"
cd /d "%PROJECT_DIR%"

set "PID_FILE=%PROJECT_DIR%tv_proxy.pid"
set "WINTUN_PID_FILE=%PROJECT_DIR%wintun_gateway.pid"
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
powershell -NoProfile -ExecutionPolicy Unrestricted -Command "Start-Process cmd.exe -ArgumentList '/c ""%~f0" admin %*"' -Verb RunAs" 2>nul
if errorlevel 1 goto :main_init
exit /b

:main_init
title ZAPRET TV ^& MOBILE BRIDGE MANAGER v1.02

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

if /i "%CLI_CMD%"=="wintun-start" goto :opt_wintun_start
if /i "%CLI_CMD%"=="wintun-stop" goto :opt_wintun_stop
if /i "%CLI_CMD%"=="wintun-routes" goto :opt_wintun_routes
if /i "%CLI_CMD%"=="wintun-status" goto :opt_wintun_status
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
echo   ZAPRET TV ^& MOBILE BRIDGE MANAGER v1.02
echo   ==================================================
echo   Wintun Gateway: !WINTUN_STATUS_STR!
echo   TV ^& Mobile:   !STATUS_STR!
echo   Legacy Winws:   !ZAPRET_STATUS_STR!
if "!IS_RUNNING!"=="1" (
    echo   Address:        http://!HOST_PORT!/
    echo   PAC URL:        http://!HOST_PORT!/proxy.pac
    echo   Smart TV:       IP !LOCAL_IP!  Port !LOCAL_PORT!
)
echo   Directory:      %PROJECT_DIR%
echo   --------------------------------------------------
echo.
echo   :: WINTUN L3 GATEWAY (SPLIT TUNNELING - RECOMMENDED)
echo      1. Start Wintun Gateway [Isolated L3 TUN + Tun2socks]
echo      2. Stop Wintun Gateway [Clean ^& Restore Routes]
echo      3. View Active Wintun Subnets ^& Routes
echo.
echo   :: TV ^& MOBILE BRIDGE (LOCAL PROXY)
echo      4. Start Bridge [Background]
echo      5. Stop Bridge
echo      6. Restart Bridge
echo      7. Check Status ^& Connection URLs
echo.
echo   :: SETTINGS ^& OPTIMIZATION
echo      8. Windows Startup              !STARTUP_STATUS!
echo      9. Optimize Windows 11 Network [RSC, QUIC, Kyber, IPv6]
echo      10. Fix Windows Proxy [Protect Dev Tools]
echo      11. Generate New Telegram MTProto Key
echo      12. Open Routing Lists Folder
echo.
echo   :: TOOLS ^& LOGS
echo      13. Open Web Dashboard in Browser
echo      14. View Live Logs [tv_proxy.log]
echo      15. Run Diagnostics ^& DoH Latency Test
echo.
echo   :: LEGACY WINWS SERVICE
echo      16. Install Legacy Zapret Service [Winws Mode]
echo      17. Remove Legacy Zapret Service
echo   --------------------------------------------------
echo      0. Exit
echo   --------------------------------------------------
echo.

set "CHOICE="
set /p CHOICE="   Select option [0-17]: "

if not defined CHOICE goto :menu_loop
if "%CHOICE%"=="1" goto :opt_wintun_start
if "%CHOICE%"=="2" goto :opt_wintun_stop
if "%CHOICE%"=="3" goto :opt_wintun_routes
if "%CHOICE%"=="4" goto :opt_start
if "%CHOICE%"=="5" goto :opt_stop
if "%CHOICE%"=="6" goto :opt_restart
if "%CHOICE%"=="7" goto :opt_status
if "%CHOICE%"=="8" goto :opt_startup
if "%CHOICE%"=="9" goto :opt_optimize
if "%CHOICE%"=="10" goto :opt_fix_proxy
if "%CHOICE%"=="11" goto :opt_tg_secret
if "%CHOICE%"=="12" goto :opt_lists
if "%CHOICE%"=="13" goto :opt_dashboard
if "%CHOICE%"=="14" goto :opt_logs
if "%CHOICE%"=="15" goto :opt_test
if "%CHOICE%"=="16" goto :opt_install_zapret
if "%CHOICE%"=="17" goto :opt_remove_zapret
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

set "WINTUN_STATUS_STR=[STOPPED]"
if exist "%WINTUN_PID_FILE%" (
    for /f "usebackq delims=" %%w in ("%WINTUN_PID_FILE%") do (
        tasklist /FI "PID eq %%w" 2>nul | findstr /i "%%w" >nul
        if not errorlevel 1 (
            set "WINTUN_STATUS_STR=[RUNNING - PID: %%w]"
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
:: 1. START WINTUN GATEWAY (SPLIT TUNNELING)
:: -----------------------------------------------------------------------------
:opt_wintun_start
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --wintun-start
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --wintun-start
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 2. STOP WINTUN GATEWAY
:: -----------------------------------------------------------------------------
:opt_wintun_stop
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --wintun-stop
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --wintun-stop
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 3. VIEW WINTUN ROUTES
:: -----------------------------------------------------------------------------
:opt_wintun_routes
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --wintun-routes
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --wintun-routes
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:opt_wintun_status
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --wintun-status
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --wintun-status
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 4. START TV & MOBILE BRIDGE
:: -----------------------------------------------------------------------------
:opt_start
if "!IS_RUNNING!"=="1" (
    echo.
    echo [i] Bridge is ALREADY RUNNING (PID: !CURRENT_PID!)
    echo.
    if defined CLI_CMD exit /b
    pause
    goto :menu_loop
)

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
:: 5. STOP TV & MOBILE BRIDGE
:: -----------------------------------------------------------------------------
:opt_stop
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
:: 6. RESTART TV & MOBILE BRIDGE
:: -----------------------------------------------------------------------------
:opt_restart
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
:: 7. CHECK STATUS
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
:: 8. WINDOWS STARTUP
:: -----------------------------------------------------------------------------
:opt_startup
cls
if exist "%SHORTCUT_PATH%" (
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
:: 9. OPTIMIZE WINDOWS 11 NETWORK (RSC, QUIC, KYBER, IPV6)
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
:: 10. FIX WINDOWS PROXY
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
:: 11. GENERATE NEW TELEGRAM KEY
:: -----------------------------------------------------------------------------
:opt_tg_secret
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --secret
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --secret
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 12. OPEN LISTS FOLDER
:: -----------------------------------------------------------------------------
:opt_lists
if exist "%PROJECT_DIR%lists" (
    start "" "%PROJECT_DIR%lists"
) else (
    echo [i] Folder lists does not exist.
)
if defined CLI_CMD exit /b
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 13. OPEN DASHBOARD IN BROWSER
:: -----------------------------------------------------------------------------
:opt_dashboard
call :refresh_status
start "" "http://!HOST_PORT!/"
if defined CLI_CMD exit /b
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 14. LIVE LOGS
:: -----------------------------------------------------------------------------
:opt_logs
cls
echo [*] Viewing live logs (Press Ctrl+C to stop)...
echo.
powershell -NoProfile -ExecutionPolicy Unrestricted -Command "Get-Content -Wait -Tail 30 '%LOG_FILE%'"
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 15. DIAGNOSTICS & DOH TEST
:: -----------------------------------------------------------------------------
:opt_test
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --test
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --test
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 16. INSTALL LEGACY ZAPRET SERVICE
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
:: 17. REMOVE LEGACY ZAPRET SERVICE
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

:opt_firewall
cls
if "!USE_STANDALONE!"=="1" (
    "%BRIDGE_EXE%" --firewall
) else (
    python.exe "%PROJECT_DIR%zapret_tv_bridge.py" --firewall
)
if defined CLI_CMD exit /b
echo.
pause
goto :menu_loop
