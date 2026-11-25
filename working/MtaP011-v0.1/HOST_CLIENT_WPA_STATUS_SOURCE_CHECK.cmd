@echo off
cd /d "%~dp0"
python -B host\client_wpa_status_readonly.py
exit /b %errorlevel%
