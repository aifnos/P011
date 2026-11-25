@echo off
cd /d "%~dp0"
py -3.12 -I -B "%~dp0host\receive_filecenter_navigation_v1_source_check.py" %*
exit /b %errorlevel%
