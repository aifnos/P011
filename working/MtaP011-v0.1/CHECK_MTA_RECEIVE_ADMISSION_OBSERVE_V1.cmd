@echo off
setlocal
cd /d "%~dp0"
python -I -B host\device_receive_admission_observe_v1_check.py %*
set "MTA_OBSERVE_EXIT=%ERRORLEVEL%"
echo MTA_RECEIVE_ADMISSION_OBSERVE_CHECKER_EXIT=%MTA_OBSERVE_EXIT%
exit /b %MTA_OBSERVE_EXIT%
