@echo off
setlocal
cd /d "%~dp0"
python -I -B host\send_failed_preflight_directory_cleanup_v1_host_check.py --run-host
set "MTA_CHECK_EXIT=%ERRORLEVEL%"
echo One modeled HOST method only. No P011 or RF test.
exit /b %MTA_CHECK_EXIT%

