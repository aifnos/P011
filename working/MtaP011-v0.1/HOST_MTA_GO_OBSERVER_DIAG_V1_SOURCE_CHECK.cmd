@echo off
setlocal
cd /d "%~dp0"
rem Fixed PC SOURCE only; no argument forwarding, device, stage, RF or old tests.
py -3.12 -I -B "host\device_go_observer_diag_v1_check.py" --source-only
set "MTA_EXIT=%ERRORLEVEL%"
echo CHECKER_EXIT=%MTA_EXIT%
exit /b %MTA_EXIT%
