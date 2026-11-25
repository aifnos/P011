@echo off
setlocal
cd /d "%~dp0"
rem Explicit single 20s display-only smoke with passive after-return cache; no RF/stage.
py -3.12 -I -B "host\device_formal_send_repair_ui_preflight_v1_check.py" --check-device
set "MTA_EXIT=%ERRORLEVEL%"
echo CHECKER_EXIT=%MTA_EXIT%
exit /b %MTA_EXIT%
