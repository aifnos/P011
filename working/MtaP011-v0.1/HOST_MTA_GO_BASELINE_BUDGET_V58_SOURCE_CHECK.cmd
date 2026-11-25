@echo off
setlocal
cd /d "%~dp0"
python -I -B host\go_baseline_budget_v58_p011.py
exit /b %errorlevel%
