@echo off
setlocal
cd /d "%~dp0"
echo ===== MotoHub diagnostic =====
echo.
py --version
echo.
echo Proxy variables:
set | findstr /I "proxy"
echo.
echo Pip configuration:
py -m pip config debug
echo.
pause
