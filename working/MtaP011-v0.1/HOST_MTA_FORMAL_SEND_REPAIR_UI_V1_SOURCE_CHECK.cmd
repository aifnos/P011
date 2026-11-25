@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only; no forwarded arguments, stage, device, RF or old tests.
py -3.12 -I -B "host\device_formal_send_repair_ui_v1_check.py"
set "MTA_EXIT=%ERRORLEVEL%"
echo CHECKER_EXIT=%MTA_EXIT%
exit /b %MTA_EXIT%
