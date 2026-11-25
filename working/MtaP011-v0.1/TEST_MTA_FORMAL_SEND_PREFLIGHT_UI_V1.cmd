@echo off
setlocal
cd /d "%~dp0"
rem Explicit 20-second UI smoke; no asset stage, RF, phone or old tests.
py -3.12 -I -B "host\device_formal_send_preflight_ui_v1_check.py" --check-device
set "MTA_EXIT=%ERRORLEVEL%"
echo CHECKER_EXIT=%MTA_EXIT%
exit /b %MTA_EXIT%
