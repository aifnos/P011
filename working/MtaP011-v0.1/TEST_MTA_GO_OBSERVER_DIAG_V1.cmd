@echo off
setlocal
cd /d "%~dp0"
rem Fixed files-only stage; only its zero exit permits one original Parent preflight.
rem No argument forwarding, Owner, UI, transfer, RF, repair, cleanup or old tests.
py -3.12 -I -B "host\device_go_observer_diag_v1_check.py" --stage-device
set "MTA_STAGE_EXIT=%ERRORLEVEL%"
echo OBSERVER_DIAG_STAGE_EXIT=%MTA_STAGE_EXIT%
if not "%MTA_STAGE_EXIT%"=="0" exit /b %MTA_STAGE_EXIT%
py -3.12 -I -B "host\device_go_observer_diag_v1_check.py" --check-device
set "MTA_EXIT=%ERRORLEVEL%"
echo OBSERVER_DIAG_PARENT_EXIT=%MTA_EXIT%
exit /b %MTA_EXIT%
