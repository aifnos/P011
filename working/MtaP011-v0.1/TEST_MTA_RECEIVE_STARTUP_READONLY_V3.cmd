@echo off
setlocal
rem Independent v3 startup observation only; RF gates remain closed.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_startup_readonly_v3_check.py" --check-device %*
exit /b %errorlevel%
