@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\go_send_finish_observer_v85_check.py"
set "MTA_HOST85_EXIT=%ERRORLEVEL%"
echo HOST-only affected checks finished. No P011 or phone action.
pause
exit /b %MTA_HOST85_EXIT%
