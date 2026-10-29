@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1
title ОСТАНОВКА И ОЧИСТКА ВСЕХ СЛУЖБ СТАРОЙ ВЕРСИИ

:: Проверка прав Администратора и авто-повышение
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Запрос прав Администратора...
    powershell -NoProfile -ExecutionPolicy Unrestricted -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cls
echo ======================================================================
echo    ОЧИСТКА И ОСТАНОВКА ВСЕХ СЛУЖБ И ПРОЦЕССОВ ПРЕДЫДУЩИХ ВЕРСИЙ
echo ======================================================================
echo.

echo [*] 1. Завершение фоновых процессов (winws, tun2socks, ZapretTVBridge)...
taskkill /F /IM winws.exe >nul 2>&1
taskkill /F /IM tun2socks.exe >nul 2>&1
taskkill /F /IM ZapretTVBridge.exe >nul 2>&1
taskkill /F /IM 3proxy.exe >nul 2>&1
echo [+] Все фоновые процессы завершены.

echo.
echo [*] 2. Остановка и полное удаление старых служб Windows...
sc stop zapret >nul 2>&1
sc delete zapret >nul 2>&1
sc stop WinDivert >nul 2>&1
sc delete WinDivert >nul 2>&1
sc stop WinDivert14 >nul 2>&1
sc delete WinDivert14 >nul 2>&1
sc stop wintun >nul 2>&1
sc delete wintun >nul 2>&1
echo [+] Службы zapret и драйверы WinDivert удалены.

echo.
echo [*] 3. Сброс службы маршрутизации RemoteAccess в исходное состояние...
sc stop RemoteAccess >nul 2>&1
sc config RemoteAccess start= demand >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IPEnableRouter" /t REG_DWORD /d 0 /f >nul 2>&1
netsh int ip set global icmpredirects=enabled >nul 2>&1
echo [+] Служба RemoteAccess остановлена, IP-маршрутизация отключена.

echo.
echo [*] 4. Удаление старых сетевых интерфейсов и маршрутов Wintun...
netsh interface delete interface name="WintunGateway" >nul 2>&1
route delete 172.19.0.0 >nul 2>&1
echo [+] Виртуальные интерфейсы и маршруты очищены.

echo.
echo [*] 5. Удаление старой версии из автозагрузки Windows...
schtasks /delete /tn "Zapret_TV_Bridge" /f >nul 2>&1
del /f /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Zapret_TV_Bridge.lnk" >nul 2>&1
del /f /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\*zapret*.lnk" >nul 2>&1
del /f /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\*bridge*.lnk" >nul 2>&1
del /f /q "%LOCALAPPDATA%\ZapretTVBridge\bridge_autostart.vbs" >nul 2>&1
echo [+] Задачи планировщика и ярлыки автозагрузки удалены.

echo.
echo [*] 6. Сброс системного прокси и очистка политик браузеров...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "AutoConfigURL" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyEnable" /t REG_DWORD /d 0 /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Yandex\YandexBrowser" /f >nul 2>&1
echo [+] Системный прокси отключен, политики браузеров очищены.

echo.
echo [*] 7. Очистка кэша DNS...
ipconfig /flushdns >nul 2>&1
echo [+] Кэш DNS очищен.

echo.
echo ======================================================================
echo [+] ВСЕ СТАРЫЕ СЛУЖБЫ И КОНФЛИКТНЫЕ НАСТРОЙКИ УСПЕШНО УДАЛЕНЫ!
echo ======================================================================
echo.
echo Теперь система полностью чиста. Новая версия программы не будет
echo конфликтовать со старыми службами и портами.
echo.
echo Нажмите любую клавишу для закрытия...
pause >nul
