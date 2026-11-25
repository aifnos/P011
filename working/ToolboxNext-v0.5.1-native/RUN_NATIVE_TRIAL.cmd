@echo off
cd /d "%~dp0"
python -B host\native_trial.py start --seconds 600
set "P011_NATIVE_EXIT=%ERRORLEVEL%"
echo.
echo Finite native trial: up to 10 minutes. Stock UI stays running.
echo Use COLLECT_NATIVE_RESULTS.cmd after exiting on the pen.
pause
exit /b %P011_NATIVE_EXIT%
