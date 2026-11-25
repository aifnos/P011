@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B host\device_receive_probe_provenance.py --check-device
set "mta_probe_exit=%ERRORLEVEL%"
echo Read-only new probe functions. No receiver, RF, staging, or phone transfer.
pause
exit /b %mta_probe_exit%
