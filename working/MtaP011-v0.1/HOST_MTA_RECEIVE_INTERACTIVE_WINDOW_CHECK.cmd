@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\receive_interactive_window_check.py"
set "MTA_WINDOW_EXIT=%ERRORLEVEL%"
echo HOST_MTA_RECEIVE_INTERACTIVE_WINDOW_EXIT=%MTA_WINDOW_EXIT%
exit /b %MTA_WINDOW_EXIT%
