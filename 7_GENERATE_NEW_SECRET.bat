@echo off
setlocal
chcp 65001 >nul 2>&1

set "PROJECT_DIR=%~dp0"
cd /d "%PROJECT_DIR%"

:: Find python
set "PYTHON_EXE="
for /f "tokens=*" %%i in ('where python.exe 2^>nul') do (
    if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
)
if not defined PYTHON_EXE (
    for /f "tokens=*" %%i in ('where py.exe 2^>nul') do (
        if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
    )
)
if not defined PYTHON_EXE (
    for /d %%d in ("%LOCALAPPDATA%\Programs\Python\Python*") do (
        if exist "%%d\python.exe" set "PYTHON_EXE=%%d\python.exe"
    )
)
if not defined PYTHON_EXE set "PYTHON_EXE=python.exe"

"%PYTHON_EXE%" "%PROJECT_DIR%generate_new_tg_secret.py"

echo.
pause
