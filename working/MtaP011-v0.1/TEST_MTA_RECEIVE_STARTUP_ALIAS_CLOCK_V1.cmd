@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: isolated graph75 diagnostic60+60 startup-close; no UI/RF/phone.
py -3.12 -I -B "host\device_receive_startup_alias_clock_v1_check.py" --check-device %*
exit /b %errorlevel%
