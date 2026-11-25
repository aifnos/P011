@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only by default; no ADB, UI, RF or phone action.
py -3.12 -I -B "host\device_receive_durable_state_v1_startup_check.py" %*
exit /b %errorlevel%
