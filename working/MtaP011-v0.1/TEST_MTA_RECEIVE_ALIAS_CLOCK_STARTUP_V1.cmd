@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: original diagnostic60+60 stage/Boot/Owner/startup/close; no RF/phone/UI.
py -3.12 -I -B "host\device_receive_alias_clock_startup_v1_check.py" --check-device %*
exit /b %errorlevel%
