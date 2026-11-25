@echo off
cd /d "%~dp0"
py -3.12 -I -B host\device_receive_radio_baseline_check.py --check-device
exit /b %errorlevel%
