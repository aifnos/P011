@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B host\device_receive_proc_freezer_v2_capture_check.py --capture-only
exit /b %errorlevel%
