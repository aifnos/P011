@echo off
cd /d "%~dp0"
py -B host\client_init_prepare_v10_p011.py
exit /b %errorlevel%
