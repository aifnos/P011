@echo off
cd /d "%~dp0"
py -3 -I -B host\receive_directory_clock_check.py
exit /b %errorlevel%
