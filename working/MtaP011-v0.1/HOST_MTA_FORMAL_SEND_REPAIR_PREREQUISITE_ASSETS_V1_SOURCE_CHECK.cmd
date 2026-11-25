@echo off
setlocal
cd /d "%~dp0"
rem Fixed PC SOURCE plans only; no arguments, device or RF.
if not "%~1"=="" exit /b 2
py -3.12 -I -B "host\device_formal_send_repair_prerequisite_assets_v1_check.py"
set "MTA_EXIT=%ERRORLEVEL%"
echo CHECKER_EXIT=%MTA_EXIT%
exit /b %MTA_EXIT%
