@echo off
cd /d "%~dp0"
py -3.12 -B host\device_receive_durable_network_v1_check.py
exit /b %errorlevel%
