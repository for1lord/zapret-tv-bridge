@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1

:: Elevate to Administrator via PowerShell if needed
net session >nul 2>&1
if errorlevel 1 (
    echo [i] Запрос прав администратора для настройки Брандмауэра Windows...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

set "PROJECT_DIR=%~dp0"
cd /d "%PROJECT_DIR%"

echo ======================================================================
echo       Zapret TV & Mobile Bridge — Первоначальная установка
echo ======================================================================
echo.

:: 1. Search for Python
echo [*] Проверка наличия Python в системе...
set "PYTHON_EXE="

:: Try standard PATH
for /f "tokens=*" %%i in ('where python.exe 2^>nul') do (
    if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
)
if not defined PYTHON_EXE (
    for /f "tokens=*" %%i in ('where py.exe 2^>nul') do (
        if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
    )
)

:: Search LocalAppData Programs
if not defined PYTHON_EXE (
    for /d %%d in ("%LOCALAPPDATA%\Programs\Python\Python*") do (
        if exist "%%d\python.exe" set "PYTHON_EXE=%%d\python.exe"
    )
)

:: Search Program Files
if not defined PYTHON_EXE (
    for /d %%d in ("%ProgramFiles%\Python*") do (
        if exist "%%d\python.exe" set "PYTHON_EXE=%%d\python.exe"
    )
)

:: Search Registry HKCU / HKLM
if not defined PYTHON_EXE (
    for /f "tokens=2* delims= " %%a in ('reg query "HKCU\Software\Python\PythonCore" /s /v "ExecutablePath" 2^>nul') do (
        if exist "%%b" set "PYTHON_EXE=%%b"
    )
)
if not defined PYTHON_EXE (
    for /f "tokens=2* delims= " %%a in ('reg query "HKLM\Software\Python\PythonCore" /s /v "ExecutablePath" 2^>nul') do (
        if exist "%%b" set "PYTHON_EXE=%%b"
    )
)

if not defined PYTHON_EXE (
    echo.
    echo [ОШИБКА] Python 3 не обнаружен на вашем компьютере!
    echo.
    echo Пожалуйста, установите Python 3 с официального сайта:
    echo    https://www.python.org/downloads/
    echo.
    echo [ВАЖНО] Во время установки ОБЯЗАТЕЛЬНО отметьте галочку:
    echo    "[X] Add python.exe to PATH"
    echo.
    pause
    exit /b 1
)

echo [+] Python найден: %PYTHON_EXE%
"%PYTHON_EXE%" --version
echo.

:: 2. Install dependencies from requirements.txt
echo [*] Проверка и установка зависимостей...
"%PYTHON_EXE%" -m pip install --quiet --upgrade pip >nul 2>&1
"%PYTHON_EXE%" -m pip install -r "%PROJECT_DIR%requirements.txt"
if errorlevel 1 (
    echo [!] Предупреждение: Не все зависимости установились автоматически.
) else (
    echo [+] Зависимости успешно установлены!
)
echo.

:: 3. Configure Windows Firewall
echo [*] Настройка правил Брандмауэра Windows...
netsh advfirewall firewall show rule name="Zapret_TV_Proxy" >nul 2>&1
if errorlevel 1 (
    netsh advfirewall firewall add rule name="Zapret_TV_Proxy" dir=in action=allow protocol=TCP localport=8080 profile=any >nul 2>&1
    echo [+] Добавлено правило Брандмауэра для порта 8080 (HTTP / PAC Proxy).
) else (
    echo [+] Правило Брандмауэра для порта 8080 уже существует.
)

netsh advfirewall firewall show rule name="TgWsProxy" >nul 2>&1
if errorlevel 1 (
    netsh advfirewall firewall add rule name="TgWsProxy" dir=in action=allow protocol=TCP localport=1443 profile=any >nul 2>&1
    echo [+] Добавлено правило Брандмауэра для порта 1443 (Telegram MTProto).
) else (
    echo [+] Правило Брандмауэра для порта 1443 уже существует.
)
echo.

:: 4. Generate initial Telegram Secret if missing
if not exist "%PROJECT_DIR%tg_secret.txt" (
    echo [*] Генерация уникального случайного MTProto-ключа для Telegram...
    "%PYTHON_EXE%" "%PROJECT_DIR%generate_new_tg_secret.py" >nul 2>&1
    echo [+] Секретный ключ успешно создан и сохранен.
) else (
    echo [+] Секретный ключ Telegram уже инициализирован.
)
echo.

echo ======================================================================
echo   [OK] Установка успешно завершена! Проект готов к работе.
echo ======================================================================
echo.
echo Для управления используйте пронумерованные файлы:
echo   • 2_START.vbs           — запустить тихо в фоне (без консольных окон)
echo   • 3_STATUS.bat          — проверить статус и получить ссылки
echo   • 4_STOP.bat            — остановить фоновый процесс
echo   • 5_ADD_TO_STARTUP.bat  — добавить в автозагрузку Windows
echo.
set /p START_NOW="Запустить фоновый мост прямо сейчас? (Y/N): "
if /i "!START_NOW!"=="Y" (
    wscript.exe "%PROJECT_DIR%2_START.vbs"
    timeout /t 2 /nobreak >nul
    call "%PROJECT_DIR%3_STATUS.bat"
)

pause
