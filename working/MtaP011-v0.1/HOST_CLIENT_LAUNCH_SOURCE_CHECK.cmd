@echo off
setlocal
cd /d "%~dp0"
python -B host\client_launch_registration_linux_check.py --source-check-only
exit /b %ERRORLEVEL%
