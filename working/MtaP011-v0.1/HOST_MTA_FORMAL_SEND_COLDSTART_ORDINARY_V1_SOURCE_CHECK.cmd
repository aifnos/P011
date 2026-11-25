@echo off
setlocal
cd /d "%~dp0"
python -I -B host\device_formal_send_coldstart_ordinary_v1_check.py
set "MTA_CHECK_EXIT=%ERRORLEVEL%"
echo SOURCE only. No P011 access requested.
exit /b %MTA_CHECK_EXIT%

