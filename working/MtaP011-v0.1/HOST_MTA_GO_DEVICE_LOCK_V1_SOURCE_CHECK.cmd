@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\device_go_device_lock_v1_check.py"
set "MTA_EXIT=%ERRORLEVEL%"
echo CHECKER_EXIT=%MTA_EXIT%
exit /b %MTA_EXIT%

