@echo off
py -3.12 -I -B "%~dp0host\go_restored_status_v73_check.py"
set "MTA_EXIT=%ERRORLEVEL%"
pause
exit /b %MTA_EXIT%
