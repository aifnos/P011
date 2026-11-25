@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: new graph75 diagnostic60+60 startup-close; no companion/UI/RF/phone.
py -3.12 -I -B "host\device_receive_filecenter_v1_startup_check.py" --check-device %*
exit /b %errorlevel%
