@echo off
setlocal
cd /d "%~dp0"
python -B host\client_resource_v23_source_check.py
exit /b %errorlevel%
