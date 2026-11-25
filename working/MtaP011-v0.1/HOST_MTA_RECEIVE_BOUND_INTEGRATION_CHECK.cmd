@echo off
cd /d "%~dp0"
py -3 -I -B host\receive_bound_integration_check.py
exit /b %errorlevel%
