@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\formal_send_ui_stop_container_check.py"
set "MTA_SEND_UI_STOP_EXIT=%ERRORLEVEL%"
echo HOST_MTA_FORMAL_SEND_UI_STOP_INTERFACE_EXIT=%MTA_SEND_UI_STOP_EXIT%
exit /b %MTA_SEND_UI_STOP_EXIT%
