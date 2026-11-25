@echo off
cd /d "%~dp0"
py -3.12 -B host\receive_network_integration_check.py %*
exit /b %errorlevel%
