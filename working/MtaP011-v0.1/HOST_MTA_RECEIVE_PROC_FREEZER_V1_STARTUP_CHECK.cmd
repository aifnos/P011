@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only; no ADB/RF/UI/phone.
py -3.12 -I -B "host\device_receive_proc_freezer_v1_startup_check.py" %*
exit /b %errorlevel%
