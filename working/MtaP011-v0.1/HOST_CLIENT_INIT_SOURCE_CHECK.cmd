@echo off
cd /d "%~dp0"
python -B host\client_init_p011.py
exit /b %errorlevel%
