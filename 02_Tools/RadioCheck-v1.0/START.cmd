@echo off
setlocal
chcp 65001 >nul
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Collect-P011.ps1" -Tag current
echo.
echo Logs and ZIP files: D:\project\P011
pause
