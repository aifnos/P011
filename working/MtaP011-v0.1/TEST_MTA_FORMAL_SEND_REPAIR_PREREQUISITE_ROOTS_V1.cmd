@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\device_formal_send_repair_prerequisite_roots_v1_check.py" --check-device
set "MTA_EXIT=%ERRORLEVEL%"
echo CHECKER_EXIT=%MTA_EXIT%
exit /b %MTA_EXIT%
