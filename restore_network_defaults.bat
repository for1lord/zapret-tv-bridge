@echo off
chcp 65001 >nul 2>&1
title RESTORE WINDOWS NETWORK DEFAULTS

:: 100% Bulletproof UAC Elevation via temporary VBScript
net session >nul 2>&1
if %errorlevel% == 0 goto :gotAdmin

echo Requesting Administrator privileges...
echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin_net.vbs"
echo UAC.ShellExecute "%~s0", "admin", "", "runas", 1 >> "%temp%\getadmin_net.vbs"
"%temp%\getadmin_net.vbs"
del "%temp%\getadmin_net.vbs" 2>nul
exit /b

:gotAdmin
pushd "%CD%"
CD /D "%~dp0"
cls
echo ==================================================
echo   ВОССТАНОВЛЕНИЕ ЗАВОДСКИХ НАСТРОЕК СЕТИ WINDOWS
echo ==================================================
echo.

echo [*] 1. Удаление принудительных политик браузеров (Edge, Chrome, Yandex)...
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Yandex\YandexBrowser" /f >nul 2>&1
echo [+] Разделы принудительных политик браузеров полностью удалены.

echo.
echo [*] 2. Включение протокола IPv6 на всех адаптерах...
powershell -NoProfile -Command "Enable-NetAdapterBinding -Name * -ComponentId ms_tcpip6 -Confirm:$false" >nul 2>&1
echo [+] Протокол IPv6 включен.

echo.
echo [*] 3. Включение RSC (Receive Segment Coalescing)...
powershell -NoProfile -Command "Enable-NetAdapterRsc -Name * -Confirm:$false" >nul 2>&1
netsh int tcp set global rsc=enabled >nul 2>&1
echo [+] RSC включен.

echo.
echo [*] 4. Восстановление TCP Auto-Tuning...
netsh int tcp set global autotuninglevel=normal >nul 2>&1
echo [+] TCP Auto-Tuning установлен в normal.

echo.
echo [*] 5. Сброс системного прокси Windows...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "AutoConfigURL" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyEnable" /t REG_DWORD /d 0 /f >nul 2>&1
echo [+] Системный прокси отключен.

echo.
echo [*] 6. Очистка кэша DNS...
ipconfig /flushdns >nul 2>&1
echo [+] Кэш DNS очищен.

echo.
echo ==================================================
echo [+] ВСЕ ЗАВОДСКИЕ НАСТРОЙКИ СЕТИ УСПЕШНО ВОССТАНОВЛЕНЫ!
echo ==================================================
echo.
echo Теперь закройте и снова откройте браузер (Edge / Chrome).
echo Все сайты (Twitch, YouTube и др.) будут открываться в штатном режиме.
echo.
pause
