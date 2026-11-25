@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B host\formal_send_status_presentation_v1_host_check.py
exit /b %errorlevel%
