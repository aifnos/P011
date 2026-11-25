@echo off
setlocal
cd /d "%~dp0"
python -I -B host\device_formal_send_status_ui_v1_check.py --check-device
set "MTA_EXIT=%ERRORLEVEL%"
exit /b %MTA_EXIT%
