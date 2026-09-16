@echo off
setlocal
title MotoHub Stopper
echo.
echo Stopping MotoHub...
taskkill /FI "WINDOWTITLE eq MotoHub Server" /T /F >nul 2>&1
echo MotoHub stopped.
echo.
pause
