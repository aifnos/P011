@echo off
cd /d "%~dp0"
python -B host\client_durable_connect_v19_source_check.py
exit /b %errorlevel%
