@echo off
cd /d "%~dp0"
python -B host\client_completion_v27_check.py
exit /b %errorlevel%
