@echo off
cd /d "%~dp0"
py -3.12 "%~dp0host\filecenter_close_seal_v1_check.py" %*
exit /b %errorlevel%
