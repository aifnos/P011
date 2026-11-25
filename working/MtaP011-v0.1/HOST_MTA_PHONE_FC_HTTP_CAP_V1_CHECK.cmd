@echo off
setlocal
cd /d "%~dp0"
python -I -B host\device_phone_fc_http_cap_v1_check.py
set "MTA_EXIT=%ERRORLEVEL%"
exit /b %MTA_EXIT%
