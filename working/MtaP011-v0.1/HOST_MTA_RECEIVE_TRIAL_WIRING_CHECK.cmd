@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\receive_trial_wiring_check.py"
set "MTA_HOST_EXIT=%ERRORLEVEL%"
echo HOST_MTA_RECEIVE_TRIAL_WIRING_EXIT=%MTA_HOST_EXIT%
exit /b %MTA_HOST_EXIT%
