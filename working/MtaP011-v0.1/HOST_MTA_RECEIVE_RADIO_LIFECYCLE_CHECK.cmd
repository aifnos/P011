@echo off
cd /d "%~dp0"
py -3.12 -I -B host\receive_radio_lifecycle_check.py
exit /b %errorlevel%
