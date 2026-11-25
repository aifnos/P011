@echo off
cd /d "%~dp0"
python -B host\client_dhcp_v21_source_check.py
exit /b %errorlevel%
