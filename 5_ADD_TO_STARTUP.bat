@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1

set "PROJECT_DIR=%~dp0"
set "TARGET_VBS=%PROJECT_DIR%2_START.vbs"
set "STARTUP_FOLDER=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "SHORTCUT_PATH=%STARTUP_FOLDER%\Zapret_TV_Bridge.lnk"

echo ======================================================================
echo    Zapret TV & Mobile Bridge — Настройка автозагрузки Windows
echo ======================================================================
echo.

if exist "%SHORTCUT_PATH%" (
    echo [+] Мост УЖЕ добавлен в автозагрузку Windows:
    echo     %SHORTCUT_PATH%
    echo.
    set /p CHOICE="Хотите УДАЛИТЬ его из автозагрузки? (Y/N): "
    if /i "!CHOICE!"=="Y" (
        del /f /q "%SHORTCUT_PATH%" >nul 2>&1
        echo [+] Ярлык успешно удален из автозагрузки.
    )
) else (
    echo [*] Мост пока НЕ добавлен в автозагрузку.
    echo.
    set /p CHOICE="Добавить тихий фоновый запуск в автозагрузку Windows? (Y/N): "
    if /i "!CHOICE!"=="Y" (
        powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%SHORTCUT_PATH%'); $s.TargetPath = 'wscript.exe'; $s.Arguments = '\"%TARGET_VBS%\"'; $s.WorkingDirectory = '%PROJECT_DIR%'; $s.Description = 'Zapret TV & Mobile Bridge Background Service'; $s.Save()"
        if exist "%SHORTCUT_PATH%" (
            echo [+] Ярлык успешно добавлен в автозагрузку Windows!
            echo     Сервис будет запускаться автоматически в фоне при входе в систему.
        ) else (
            echo [ОШИБКА] Не удалось создать ярлык в папке автозагрузки.
        )
    )
)

echo.
pause
