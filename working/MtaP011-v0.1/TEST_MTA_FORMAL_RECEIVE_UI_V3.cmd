@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\device_formal_receive_ui_v3_check.py" --ui-smoke %*
set "MTA_EXIT=%ERRORLEVEL%"
echo CHECKER_EXIT=%MTA_EXIT%
exit /b %MTA_EXIT%
