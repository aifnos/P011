@echo off
setlocal
cd /d "%~dp0"
rem Default PC SOURCE only. No archived main, ADB, radio or phone action.
py -3.12 -I -B "host\device_phone_handoff_durable_window_v1_check.py" %*
exit /b %errorlevel%
