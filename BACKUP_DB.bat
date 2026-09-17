@echo off
setlocal
cd /d "%~dp0"
if not exist backups mkdir backups
for /f "tokens=1-4 delims=/.- " %%a in ("%date%") do set D=%%d-%%b-%%c
set T=%time::=-%
set T=%T:.=-%
copy /Y motohub.db "backups\motohub-%D%-%T%.db" >nul
if errorlevel 1 (echo Backup failed.&pause&exit /b 1)
echo Backup created in backups\
pause
