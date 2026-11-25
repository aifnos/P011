@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\device_go_device_lock_init_v2_check.py" --initialize-device
set "MTA_EXIT=%ERRORLEVEL%"
echo INITIALIZE_EXIT=%MTA_EXIT%
exit /b %MTA_EXIT%
