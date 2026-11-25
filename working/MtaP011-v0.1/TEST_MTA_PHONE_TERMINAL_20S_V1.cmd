@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "%~dp0host\device_phone_terminal_20s_v1_check.py" --check-device
set "MTA_EXIT=%ERRORLEVEL%"
exit /b %MTA_EXIT%
