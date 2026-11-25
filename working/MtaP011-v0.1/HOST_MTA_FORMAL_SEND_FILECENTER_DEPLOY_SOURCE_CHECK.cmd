@echo off
cd /d "%~dp0"
py -3.12 -I -B host\formal_send_filecenter_deploy_source_check.py
exit /b %errorlevel%
