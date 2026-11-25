@echo off
setlocal
cd /d "%~dp0"
py -3 -I -B host\receive_lifecycle_check.py
exit /b %errorlevel%
