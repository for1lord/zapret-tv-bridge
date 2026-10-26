@echo off
setlocal
cd /d "%~dp0"

:: Check Admin rights and auto-elevate
net session >nul 2>&1
if not errorlevel 1 goto :run_config

title ЗАПРОС ПРАВ АДМИНИСТРАТОРА
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\" admin\"' -Verb RunAs" 2>nul
exit /b

:run_config
title НАСТРОЙКА WINDOWS КАК ШЛЮЗА ДЛЯ РОУТЕРА
chcp 65001 >nul

echo.
echo ==================================================
echo  НАСТРОЙКА WINDOWS КАК ШЛЮЗА ДЛЯ ВСЕХ УСТРОЙСТВ
echo ==================================================
echo.
echo [*] Включение IP-маршрутизации в реестре Windows...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IPEnableRouter /t REG_DWORD /d 1 /f

echo.
echo [*] Настройка и запуск службы маршрутизации (RemoteAccess)...
sc config RemoteAccess start= auto
sc start RemoteAccess

echo.
echo [*] Отключение ICMP Redirects...
netsh int ip set global icmpredirects=disabled

echo.
echo ==================================================
echo  [+] Настройка Windows завершена успешно!
echo.
echo  Теперь в роутере TP-Link (раздел DHCP -^> Настройки DHCP):
echo    Основной шлюз: 192.168.0.105
echo    DNS: 1.1.1.1 и 8.8.8.8
echo  и нажмите Сохранить + перезагрузите роутер.
echo ==================================================
echo.
pause
