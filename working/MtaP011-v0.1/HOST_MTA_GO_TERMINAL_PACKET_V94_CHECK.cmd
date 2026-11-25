@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "%~dp0host\go_terminal_packet_v94_check.py"
set "MTA_HOST94_EXIT=%ERRORLEVEL%"
echo HOST94 exit=%MTA_HOST94_EXIT%
if /I not "%~1"=="--no-pause" pause
exit /b %MTA_HOST94_EXIT%
