@echo off
setlocal
cd /d "%~dp0"
python -B host\client_store_close_v22_source_check.py
exit /b %errorlevel%
