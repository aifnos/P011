@echo off
setlocal
cd /d "%~dp0"
rem One fixed affected HOST classification contract; no device.
py -3.12 -I -B "host\receive_profile_classification_clock_v1_host_check.py" --run-host %*
exit /b %errorlevel%
