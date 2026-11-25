@echo off
setlocal
rem NEW Linux HOST timer/input only. No device arguments or old tests.
cd /d "%~dp0"
py -3.12 -I -B "host\formal_send_stage_bootstrap_timer_host_check.py"
set "MTA_BOOTSTRAP_TIMER_EXIT=%ERRORLEVEL%"
echo HOST_MTA_FORMAL_SEND_STAGE_BOOTSTRAP_TIMER_EXIT=%MTA_BOOTSTRAP_TIMER_EXIT%
exit /b %MTA_BOOTSTRAP_TIMER_EXIT%
