@echo off
cd /d "%~dp0"
python -B host\native_trial.py collect
set "P011_NATIVE_EXIT=%ERRORLEVEL%"
pause
exit /b %P011_NATIVE_EXIT%
