@echo off
chcp 65001 >nul 2>&1
set "PROJECT_DIR=%~dp0"
set "LOG_FILE=%PROJECT_DIR%tv_proxy.log"

echo ======================================================================
echo           Zapret TV & Mobile Bridge — Просмотр логов
echo ======================================================================
echo.

if not exist "%LOG_FILE%" (
    echo [i] Файл логов пока не создан. Запустите сервис через 2_START.vbs
    echo.
    pause
    exit /b 0
)

echo [*] Отображение последних строк лога (Ctrl+C для выхода):
echo ----------------------------------------------------------------------
powershell -NoProfile -Command "Get-Content -Path '%LOG_FILE%' -Tail 35 -Wait -Encoding utf8"
