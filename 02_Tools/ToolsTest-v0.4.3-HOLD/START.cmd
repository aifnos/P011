@echo off
setlocal
chcp 65001 >nul
title P011 Tools Test v0.4.3 - Run
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-P011.ps1" -Action Run
set "P011_EXIT=%ERRORLEVEL%"
echo.
echo P011 logs and results: D:\project\P011
pause
exit /b %P011_EXIT%
