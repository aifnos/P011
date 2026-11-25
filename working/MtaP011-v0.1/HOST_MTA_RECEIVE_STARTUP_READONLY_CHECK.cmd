@echo off
cd /d "%~dp0"
py -3.12 -I -B host\receive_startup_readonly_check.py
exit /b %errorlevel%
