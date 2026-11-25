@echo off
setlocal
cd /d "%~dp0"
python -B host\device_ip_readonly.py --check-readonly
set "mta_ip_readonly_exit=%errorlevel%"
echo.
echo Dump-only check finished. No RF or IP configuration. Review result JSON and ZIP.
pause
exit /b %mta_ip_readonly_exit%
