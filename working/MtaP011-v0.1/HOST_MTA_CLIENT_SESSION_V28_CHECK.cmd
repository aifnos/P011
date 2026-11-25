@echo off
setlocal
cd /d "%~dp0"
py -3 -B host\client_session_v28_check.py schema
if errorlevel 1 exit /b 1
py -3 -B host\client_session_v28_check.py store
exit /b %errorlevel%
