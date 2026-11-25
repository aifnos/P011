@echo off
cd /d "%~dp0"
py -3.12 -I -B "host\go_live_owner_v71_check.py"
set "P011_MTA_HOST_EXIT=%ERRORLEVEL%"
pause
exit /b %P011_MTA_HOST_EXIT%
