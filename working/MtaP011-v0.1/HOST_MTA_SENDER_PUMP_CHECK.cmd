@echo off
cd /d "%~dp0"
py -3.12 -I -B "host\sender_pump_check.py"
set "P011_MTA_PUMP_EXIT=%ERRORLEVEL%"
pause
exit /b %P011_MTA_PUMP_EXIT%
