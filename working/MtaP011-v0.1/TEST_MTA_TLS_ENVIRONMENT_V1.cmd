@echo off
cd /d "%~dp0"
py -3.12 -B host\device_tls_environment_v1_check.py --device
exit /b %errorlevel%
