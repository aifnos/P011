@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B host\receive_durable_state_v1_source_check.py
exit /b %errorlevel%
