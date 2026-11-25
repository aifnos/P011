@echo off
setlocal
cd /d "%~dp0"
rem Explicit new core75 startup-close; no RF/UI/phone.
py -3.12 -I -B "host\device_receive_proc_freezer_v1_startup_check.py" --check-device %*
exit /b %errorlevel%
