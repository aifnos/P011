@echo off
cd /d "%~dp0"
py -3.12 "%~dp0host\receive_filecenter_owner_v1_source_check.py" %*
exit /b %errorlevel%
