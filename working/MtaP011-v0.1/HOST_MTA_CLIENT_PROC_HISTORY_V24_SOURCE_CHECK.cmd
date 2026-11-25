@echo off
setlocal
cd /d "%~dp0"
python -B host\client_proc_history_v24_source_check.py
exit /b %errorlevel%
