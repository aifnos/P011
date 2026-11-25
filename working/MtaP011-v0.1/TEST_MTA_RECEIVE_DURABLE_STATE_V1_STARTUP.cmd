@echo off
setlocal
cd /d "%~dp0"
rem ROOT: exact absent core75 preparation and original closed startup-close, no RF/UI/phone.
py -3.12 -I -B "host\device_receive_durable_state_v1_startup_check.py" --check-device %*
exit /b %errorlevel%
