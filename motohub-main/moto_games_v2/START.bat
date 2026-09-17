@echo off
setlocal EnableExtensions
title MotoHub Launcher - CMD
cd /d "%~dp0"

echo ========================================
echo          MotoHub - CMD Launcher
echo ========================================
echo.

where py >nul 2>nul
if not errorlevel 1 (
    set "PYTHON=py"
) else (
    where python >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] Python 3.11+ not found.
        pause
        exit /b 1
    )
    set "PYTHON=python"
)

REM Clear proxy/SOCKS variables for this CMD process only.
set "HTTP_PROXY="
set "HTTPS_PROXY="
set "ALL_PROXY="
set "http_proxy="
set "https_proxy="
set "all_proxy="
set "PIP_PROXY="
set "PIP_INDEX_URL="
set "PIP_EXTRA_INDEX_URL="
set "PIP_CONFIG_FILE=NUL"
set "NO_PROXY="

echo [1/4] Preparing Python environment...
if not exist ".venv\Scripts\python.exe" (
    %PYTHON% -m venv .venv
    if errorlevel 1 goto :error
)

echo [2/4] Installing dependencies...
echo.
".venv\Scripts\python.exe" -m pip install --isolated --disable-pip-version-check --no-cache-dir --proxy "" --index-url "https://pypi.org/simple" -r requirements.txt
if errorlevel 1 (
    echo.
    echo Retrying...
    ".venv\Scripts\python.exe" -m pip install --isolated --disable-pip-version-check --no-cache-dir --proxy="" --index-url="https://pypi.org/simple" -r requirements.txt
    if errorlevel 1 goto :error
)

if not exist ".env" (
    echo [3/4] Creating .env...
    copy /Y ".env.example" ".env" >nul
) else (
    echo [3/4] .env already exists.
)

echo [4/4] Starting MotoHub...
echo.
echo Server: http://127.0.0.1:8000
echo Starting in a separate CMD window...
echo.

REM Server is started ONLY through cmd.exe. No PowerShell.
start "MotoHub Server" cmd.exe /k "cd /d ""%~dp0"" && "".venv\Scripts\python.exe"" run.py"

timeout /t 3 /nobreak >nul
start "" http://127.0.0.1:8000

echo.
echo MotoHub is running.
echo Server logs are in the "MotoHub Server" CMD window.
echo Use STOP.bat to stop it.
echo.
pause
exit /b 0

:error
echo.
echo ========================================
echo       MotoHub installation failed
echo ========================================
echo.
echo CMD-only launcher was used.
echo PowerShell was NOT used.
echo.
echo Run DIAGNOSE.bat and send me the output.
echo.
pause
exit /b 1
