@echo off
setlocal
cd /d "%~dp0"
py -3 -B host\client_session_v28_r2_check.py lifecycle
exit /b %errorlevel%
