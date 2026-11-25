@echo off
cd /d "%~dp0"
python -B host\client_readonly_diagnostic_v17_p011.py
exit /b %errorlevel%
