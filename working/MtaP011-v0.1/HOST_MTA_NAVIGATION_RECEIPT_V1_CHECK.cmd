@echo off
setlocal
cd /d "%~dp0"
rem One HOST receipt parser fixture only. No device or runtime main.
py -3.12 -I -B "host\receive_navigation_receipt_v1_host_check.py"
exit /b %errorlevel%
