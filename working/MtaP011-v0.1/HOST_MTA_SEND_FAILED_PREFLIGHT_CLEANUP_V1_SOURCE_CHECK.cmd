@echo off
setlocal
cd /d "%~dp0"
python -I -B host\send_failed_preflight_directory_cleanup_v1_host_check.py
set "MTA_CHECK_EXIT=%ERRORLEVEL%"
echo SOURCE only. No device or modeled HOST method was requested.
exit /b %MTA_CHECK_EXIT%

