@echo off
cd /d "%~dp0"
py -3.12 -B host\receive_durable_network_v1_check.py --run
exit /b %errorlevel%
