@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1

set "PROJECT_DIR=%~dp0"
cd /d "%PROJECT_DIR%"

set "PID_FILE=%PROJECT_DIR%tv_proxy.pid"
set "IP_FILE=%PROJECT_DIR%tv_proxy.ip"
set "SECRET_FILE=%PROJECT_DIR%tg_secret.txt"
set "LOG_FILE=%PROJECT_DIR%tv_proxy.log"
set "TARGET_VBS=%PROJECT_DIR%2_START.vbs"
set "STARTUP_FOLDER=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "SHORTCUT_PATH=%STARTUP_FOLDER%\Zapret_TV_Bridge.lnk"

:: Check Admin rights and auto-elevate if requested
if "%1"=="admin" goto :main_menu
net session >nul 2>&1
if not errorlevel 1 (
    goto :main_menu
)

:request_admin
title ZAPRET TV ^& MOBILE BRIDGE MANAGER
echo Requesting administrator privileges...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\" admin\"' -Verb RunAs"
exit /b

:main_menu
title Администратор: ZAPRET TV ^& MOBILE BRIDGE MANAGER v1.01

:menu_loop
cls

:: Check Bridge Process Status
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

:: Read Local Host:Port
set "HOST_PORT=127.0.0.1:8080"
if exist "%IP_FILE%" (
    for /f "usebackq delims=" %%i in ("%IP_FILE%") do set "HOST_PORT=%%i"
)
for /f "tokens=1,2 delims=:" %%a in ("!HOST_PORT!") do (
    set "LOCAL_IP=%%a"
    set "LOCAL_PORT=%%b"
)

:: Check Startup Status
set "STARTUP_STATUS=[disabled]"
if exist "%SHORTCUT_PATH%" set "STARTUP_STATUS=[enabled]"

:: Check Telegram Secret
set "TG_SECRET="
if exist "%SECRET_FILE%" (
    for /f "usebackq delims=" %%s in ("%SECRET_FILE%") do set "TG_SECRET=%%s"
)

echo.
echo   ================================================
echo   ZAPRET TV ^& MOBILE BRIDGE MANAGER v1.0.4
echo   ================================================
if "!IS_RUNNING!"=="1" (
    echo   :: СТАТУС:    !STATUS_STR!
    echo   :: АДРЕС:     http://!HOST_PORT!/
) else (
    echo   :: СТАТУС:    !STATUS_STR!
    echo   :: АДРЕС:     Не активен
)
echo   ------------------------------------------------
echo.
echo   :: SERVICE
echo      1. Start Bridge (Background)
echo      2. Stop Bridge
echo      3. Restart Bridge
echo      4. Check Status ^& Connection URLs
echo.
echo   :: SETTINGS ^& AUTORUN
echo      5. Windows Startup              !STARTUP_STATUS!
echo      6. Generate New TG MTProto Key
echo      7. Run Initial Setup (Firewall / Python)
echo.
echo   :: TOOLS ^& LOGS
echo      8. Open Web Dashboard in Browser
echo      9. View Real-time Live Logs
echo      10. Test Network ^& DNS/DoH
echo.
echo   ------------------------------------------------
echo      0. Exit
echo   ------------------------------------------------
echo.

set "CHOICE="
set /p CHOICE="Select option (0-10): "

if not defined CHOICE goto :menu_loop
if "%CHOICE%"=="1" goto :opt_start
if "%CHOICE%"=="2" goto :opt_stop
if "%CHOICE%"=="3" goto :opt_restart
if "%CHOICE%"=="4" goto :opt_status
if "%CHOICE%"=="5" goto :opt_startup
if "%CHOICE%"=="6" goto :opt_tg_secret
if "%CHOICE%"=="7" goto :opt_setup
if "%CHOICE%"=="8" goto :opt_dashboard
if "%CHOICE%"=="9" goto :opt_logs
if "%CHOICE%"=="10" goto :opt_test
if "%CHOICE%"=="0" exit /b
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 1. START
:: -----------------------------------------------------------------------------
:opt_start
cls
echo.
echo [*] Запуск Zapret TV ^& Mobile Bridge в тихом фоновом режиме...
if "!IS_RUNNING!"=="1" (
    echo [i] Сервис уже запущен (PID: !CURRENT_PID!).
    timeout /t 2 >nul
    goto :menu_loop
)

if exist "%TARGET_VBS%" (
    wscript.exe "%TARGET_VBS%"
) else (
    start /b "" pythonw.exe "%PROJECT_DIR%zapret_tv_bridge.py" --daemon
)

timeout /t 2 /nobreak >nul
echo [+] Сервис запущен. Проверка активности...
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 2. STOP
:: -----------------------------------------------------------------------------
:opt_stop
cls
echo.
echo [*] Остановка Zapret TV ^& Mobile Bridge...
call "%PROJECT_DIR%4_STOP.bat"
timeout /t 1 >nul
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 3. RESTART
:: -----------------------------------------------------------------------------
:opt_restart
cls
echo.
echo [*] Перезапуск моста...
call "%PROJECT_DIR%4_STOP.bat"
timeout /t 1 /nobreak >nul
if exist "%TARGET_VBS%" (
    wscript.exe "%TARGET_VBS%"
) else (
    start /b "" pythonw.exe "%PROJECT_DIR%zapret_tv_bridge.py" --daemon
)
timeout /t 2 /nobreak >nul
echo [+] Мост успешно перезапущен.
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 4. STATUS
:: -----------------------------------------------------------------------------
:opt_status
cls
echo ======================================================================
echo           Zapret TV ^& Mobile Bridge -- Статус сервиса
echo ======================================================================
echo.
if "!IS_RUNNING!"=="1" (
    echo [ СТАТУС ]: АКТИВЕН (Работает в фоне, PID: !CURRENT_PID!)
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
    echo  3. Smart TV (LG webOS / Samsung Tizen / Android TV / Apple TV):
    echo     IP-адрес: !LOCAL_IP!
    echo     Порт:     !LOCAL_PORT!
    echo.
    if defined TG_SECRET (
        set "TG_LINK=tg://proxy?server=!LOCAL_IP!^&port=1443^&secret=dd!TG_SECRET!"
        echo  4. Telegram MTProto (1 клик):
        echo     !TG_LINK!
        echo.
    )
) else (
    echo [ СТАТУС ]: ОСТАНОВЛЕН (Фоновый процесс не запущен)
    echo.
    echo Чтобы запустить сервис, выберите пункт 1 в меню.
)
echo ======================================================================
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 5. STARTUP TOGGLE
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
    set /p DEL_CHOICE="Удалить из автозагрузки? (Y/N): "
    if /i "!DEL_CHOICE!"=="Y" (
        del /f /q "%SHORTCUT_PATH%" >nul 2>&1
        echo [+] Ярлык успешно удален из автозагрузки.
    )
) else (
    echo [*] Мост пока НЕ добавлен в автозагрузку.
    echo.
    set /p ADD_CHOICE="Добавить тихий фоновый запуск в автозагрузку? (Y/N): "
    if /i "!ADD_CHOICE!"=="Y" (
        powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%SHORTCUT_PATH%'); $s.TargetPath = 'wscript.exe'; $s.Arguments = '\"%TARGET_VBS%\"'; $s.WorkingDirectory = '%PROJECT_DIR%'; $s.Description = 'Zapret TV & Mobile Bridge Background Service'; $s.Save()"
        if exist "%SHORTCUT_PATH%" (
            echo [+] Ярлык успешно добавлен в автозагрузку Windows!
        ) else (
            echo [ОШИБКА] Не удалось создать ярлык.
        )
    )
)
echo.
pause
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 6. TG SECRET
:: -----------------------------------------------------------------------------
:opt_tg_secret
cls
echo.
call "%PROJECT_DIR%7_GENERATE_NEW_SECRET.bat"
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 7. SETUP
:: -----------------------------------------------------------------------------
:opt_setup
cls
echo.
call "%PROJECT_DIR%1_SETUP.bat"
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 8. OPEN DASHBOARD
:: -----------------------------------------------------------------------------
:opt_dashboard
if "!IS_RUNNING!"=="1" (
    start http://!HOST_PORT!/
) else (
    echo.
    echo [i] Сервис не запущен. Сначала запустите мост (пункт 1).
    timeout /t 2 >nul
)
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 9. VIEW LOGS
:: -----------------------------------------------------------------------------
:opt_logs
cls
echo ======================================================================
echo           Zapret TV ^& Mobile Bridge -- Журнал работы (Live Logs)
echo ======================================================================
echo.
if not exist "%LOG_FILE%" (
    echo [i] Файл логов пока не создан. Запустите мост (пункт 1).
    echo.
    pause
    goto :menu_loop
)
echo [*] Отображение последних строк лога (Нажмите Ctrl+C для выхода):
echo ----------------------------------------------------------------------
powershell -NoProfile -Command "Get-Content -Path '%LOG_FILE%' -Tail 30 -Wait -Encoding utf8"
goto :menu_loop

:: -----------------------------------------------------------------------------
:: 10. TEST NETWORK
:: -----------------------------------------------------------------------------
:opt_test
cls
echo ======================================================================
echo           Zapret TV ^& Mobile Bridge -- Диагностика сети
echo ======================================================================
echo.
echo [*] Проверка DoH (Cloudflare 1.1.1.1)...
powershell -NoProfile -Command "$wc = New-Object System.Net.WebClient; try { $res = $wc.DownloadString('https://1.1.1.1/dns-query?name=youtube.com'); Write-Host '[OK] DoH Cloudflare доступен' -ForegroundColor Green } catch { Write-Host '[FAIL] Ошибка подключения к Cloudflare DoH' -ForegroundColor Red }"

echo [*] Проверка DoH (Google dns.google)...
powershell -NoProfile -Command "$wc = New-Object System.Net.WebClient; try { $res = $wc.DownloadString('https://dns.google/resolve?name=youtube.com'); Write-Host '[OK] DoH Google доступен' -ForegroundColor Green } catch { Write-Host '[FAIL] Ошибка подключения к Google DoH' -ForegroundColor Red }"

if "!IS_RUNNING!"=="1" (
    echo [*] Проверка локального HTTP-прокси (127.0.0.1:!LOCAL_PORT!)...
    powershell -NoProfile -Command "$proxy = New-Object System.Net.WebProxy('http://127.0.0.1:!LOCAL_PORT!'); $client = New-Object System.Net.WebClient; $client.Proxy = $proxy; try { $str = $client.DownloadString('http://127.0.0.1:!LOCAL_PORT!/proxy.pac'); Write-Host '[OK] Локальный PAC-прокси отвечает корректно' -ForegroundColor Green } catch { Write-Host '[FAIL] Ошибка ответа локального прокси' -ForegroundColor Red }"
)
echo.
pause
goto :menu_loop
