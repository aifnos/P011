@echo off
cd /d "%~dp0"
python -B host\verify_host.py
pause
