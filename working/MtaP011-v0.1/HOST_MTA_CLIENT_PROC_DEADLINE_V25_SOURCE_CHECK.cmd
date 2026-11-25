@echo off
cd /d "%~dp0"
python -B host\client_proc_deadline_v25_source_check.py
exit /b %errorlevel%
