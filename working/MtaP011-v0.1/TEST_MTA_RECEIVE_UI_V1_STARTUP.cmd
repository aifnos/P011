@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: new Receive UI graph75 diagnostic60+60 stage/Boot/Owner/close; no RF/UI/phone.
py -3.12 -I -B "host\device_receive_ui_v1_startup_check.py" --check-device %*
exit /b %errorlevel%
