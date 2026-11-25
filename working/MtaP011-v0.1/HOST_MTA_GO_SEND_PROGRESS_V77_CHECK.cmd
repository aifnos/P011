@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "%~dp0host\go_send_progress_v77_check.py"
set "MTA_PROGRESS77_EXIT=%ERRORLEVEL%"
echo.
echo HOST-only progress check finished with exit %MTA_PROGRESS77_EXIT%.
exit /b %MTA_PROGRESS77_EXIT%
