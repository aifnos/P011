@echo off
setlocal
cd /d "%~dp0"
python -B host\go_baseline_timing_v55_p011.py
exit /b %errorlevel%
