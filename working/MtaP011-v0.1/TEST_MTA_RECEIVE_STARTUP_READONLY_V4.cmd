@echo off
setlocal
rem Independent v4 startup observation only; RF gates remain closed.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_startup_readonly_v4_check.py" --check-device %*
exit /b %errorlevel%
