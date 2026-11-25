@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\formal_send_state_constructor_host_check.py"
set "MTA_SEND_STATE_CTOR_EXIT=%ERRORLEVEL%"
echo HOST_MTA_FORMAL_SEND_STATE_CONSTRUCTOR_EXIT=%MTA_SEND_STATE_CTOR_EXIT%
exit /b %MTA_SEND_STATE_CTOR_EXIT%
