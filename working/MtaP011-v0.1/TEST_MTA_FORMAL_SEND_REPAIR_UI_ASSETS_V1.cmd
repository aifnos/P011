@echo off
setlocal
cd /d "%~dp0"
rem Explicit fixed19 UI asset stage/readback only; no UI, Worker or RF.
if not "%~1"=="" exit /b 2
py -3.12 -I -B "host\device_formal_send_repair_ui_assets_v1_check.py" --stage-device
set "MTA_EXIT=%ERRORLEVEL%"
echo CHECKER_EXIT=%MTA_EXIT%
exit /b %MTA_EXIT%
