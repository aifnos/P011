@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only by default; fixed finite-window runner overlay, no ADB/RF/UI/phone.
py -3.12 -I -B "host\device_receive_window_clock_v1_startup_check.py" %*
exit /b %errorlevel%
