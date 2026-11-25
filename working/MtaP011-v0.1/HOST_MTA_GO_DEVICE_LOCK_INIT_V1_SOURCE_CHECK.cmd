@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\device_go_device_lock_init_v1_check.py" --source-only
set "MTA_EXIT=%ERRORLEVEL%"
echo SOURCE_EXIT=%MTA_EXIT%
exit /b %MTA_EXIT%
