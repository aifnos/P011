@echo off
cd /d "%~dp0"
python host\filecenter_deadline_v2_check.py %*
exit /b %errorlevel%
