@echo off
cd /d "%~dp0"
python -B host\device_udp_api_readonly.py --check-readonly
pause
