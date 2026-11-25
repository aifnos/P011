@echo off
cd /d "%~dp0"
py -3.12 -I -B "%~dp0host\go_send_terminal_boot_v98_check.py"
set "MTA_RESULT=%ERRORLEVEL%"
echo HOST-only. P011 and radios are not accessed.
pause
exit /b %MTA_RESULT%
