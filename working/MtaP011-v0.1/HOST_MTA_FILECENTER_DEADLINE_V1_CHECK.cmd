@echo off
cd /d "%~dp0"
python tests\test_filecenter_deadline_v1.py
exit /b %errorlevel%
