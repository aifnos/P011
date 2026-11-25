@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B host\receive_durable_state_v1_host_check.py picker
exit /b %errorlevel%
