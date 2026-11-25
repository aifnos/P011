@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 exit /b 1
rem PC SOURCE only. No device or RF trial. Do not rerun just to obtain logs.
py -3 -I -B host\go_active_budget_v64_p011.py
exit /b %errorlevel%
