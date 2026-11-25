@echo off
setlocal
cd /d "%~dp0"
python -B host\client_readonly_ipv4_v20_p011.py
exit /b %errorlevel%
