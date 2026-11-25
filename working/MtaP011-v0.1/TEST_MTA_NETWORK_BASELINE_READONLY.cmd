@echo off
cd /d "%~dp0"
py -3.12 -B host\device_receive_network_observer_check.py --check-device %*
exit /b %errorlevel%
