@echo off
cd /d "%~dp0"
py -3.12 -I -B "host\go_dhcp_setup_v74_check.py"
set "P011_MTA_HOST_EXIT=%ERRORLEVEL%"
pause
exit /b %P011_MTA_HOST_EXIT%
