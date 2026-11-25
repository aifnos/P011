@echo off
setlocal
chcp 65001 >nul
title P011 MenuTest - Run
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-P011.ps1" -Action Run
set "P011_EXIT=%ERRORLEVEL%"
echo.
echo P011 finished. Logs/results: D:\project\P011
if not "%P011_EXIT%"=="0" echo Review the error above. Do not erase or format the device.
pause
exit /b %P011_EXIT%
