@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only: new driver and exact False envelope; no graph/test/device.
py -3.12 -I -B "host\device_receive_ui_v1_startup_check.py" %*
exit /b %errorlevel%
