@echo off
setlocal
cd /d "%~dp0"
rem PC source identity check only. No ADB, target import, scan or RF.
python -B host\client_readonly_diagnostic_v47_p011.py
exit /b %errorlevel%
