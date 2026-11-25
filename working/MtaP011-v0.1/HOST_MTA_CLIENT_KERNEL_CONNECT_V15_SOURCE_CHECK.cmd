@echo off
cd /d "%~dp0"
python -B host\client_kernel_connect_v15_source_check.py
exit /b %errorlevel%
