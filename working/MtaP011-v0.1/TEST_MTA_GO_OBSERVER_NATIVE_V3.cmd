@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\device_go_observer_native_v3_check.py" --stage-device
set "MTA_STAGE_EXIT=%ERRORLEVEL%"
echo STAGE_EXIT=%MTA_STAGE_EXIT%
if not "%MTA_STAGE_EXIT%"=="0" exit /b %MTA_STAGE_EXIT%
py -3.12 -I -B "host\device_go_observer_native_v3_check.py" --check-device
set "MTA_PARENT_EXIT=%ERRORLEVEL%"
echo PARENT_EXIT=%MTA_PARENT_EXIT%
exit /b %MTA_PARENT_EXIT%
