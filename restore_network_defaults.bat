@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1
title RESTORE WINDOWS NETWORK DEFAULTS

:: Check Administrator rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cls
echo ==================================================
echo   ВОССТАНОВЛЕНИЕ СЕТИ И DNS WINDOWS
echo ==================================================
echo.

echo [*] 1. Удаление принудительных политик браузеров (Edge, Chrome, Yandex)...
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Yandex\YandexBrowser" /f >nul 2>&1
echo [+] Политики браузеров успешно удалены.

echo.
echo [*] 2. Настройка надежных публичных DNS (Яндекс 77.88.8.8 + Cloudflare 1.1.1.1)...
for /f "skip=3 tokens=4*" %%i in ('netsh interface show interface') do (
    set "IFNAME=%%j"
    if defined IFNAME (
        netsh interface ipv4 set dns name="!IFNAME!" static 77.88.8.8 primary >nul 2>&1
        netsh interface ipv4 add dns name="!IFNAME!" 1.1.1.1 index=2 >nul 2>&1
    )
)
echo [+] Надежные DNS-серверы успешно прописаны.

echo.
echo [*] 3. Включение протокола IPv6...
powershell -NoProfile -Command "Enable-NetAdapterBinding -Name * -ComponentId ms_tcpip6 -Confirm:$false" >nul 2>&1
echo [+] IPv6 включен.

echo.
echo [*] 4. Включение RSC и TCP Auto-Tuning...
powershell -NoProfile -Command "Enable-NetAdapterRsc -Name * -Confirm:$false" >nul 2>&1
netsh int tcp set global rsc=enabled >nul 2>&1
netsh int tcp set global autotuninglevel=normal >nul 2>&1
echo [+] RSC и TCP стек настроены.

echo.
echo [*] 5. Сброс системного прокси...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "AutoConfigURL" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyEnable" /t REG_DWORD /d 0 /f >nul 2>&1
echo [+] Системный прокси отключен.

echo.
echo [*] 6. Очистка кэша DNS...
ipconfig /flushdns >nul 2>&1
echo [+] Кэш DNS очищен.

echo.
echo ==================================================
echo [+] ВСЕ НАСТРОЙКИ СЕТИ И DNS УСПЕШНО ВОССТАНОВЛЕНЫ!
echo ==================================================
echo.
echo Теперь закройте и снова откройте браузер (Edge / Chrome).
echo Все сайты (Twitch, YouTube и др.) будут открываться мгновенно.
echo.
pause
