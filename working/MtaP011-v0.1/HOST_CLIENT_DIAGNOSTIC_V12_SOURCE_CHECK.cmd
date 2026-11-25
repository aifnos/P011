@echo off
cd /d "%~dp0"
py -B host\client_init_diagnostic_v12_p011.py
exit /b %errorlevel%
