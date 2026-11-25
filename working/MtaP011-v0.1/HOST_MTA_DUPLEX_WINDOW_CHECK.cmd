@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\duplex_window_host_check.py"
set "MTA_DUPLEX_WINDOW_EXIT=%ERRORLEVEL%"
echo HOST_MTA_DUPLEX_WINDOW_EXIT=%MTA_DUPLEX_WINDOW_EXIT%
exit /b %MTA_DUPLEX_WINDOW_EXIT%
