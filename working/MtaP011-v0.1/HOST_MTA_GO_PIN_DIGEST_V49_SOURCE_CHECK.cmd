@echo off
setlocal
cd /d "%~dp0"
rem PC source identity check only. No ADB, target import, scan or RF.
python -B host\go_pin_digest_v49_p011.py
exit /b %errorlevel%
