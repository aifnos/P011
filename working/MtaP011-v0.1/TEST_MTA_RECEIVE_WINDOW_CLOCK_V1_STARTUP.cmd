@echo off
setlocal
cd /d "%~dp0"
rem ROOT: original closed core75 startup-close with fixed window runner; no RF/UI/phone.
py -3.12 -I -B "host\device_receive_window_clock_v1_startup_check.py" --check-device %*
exit /b %errorlevel%
