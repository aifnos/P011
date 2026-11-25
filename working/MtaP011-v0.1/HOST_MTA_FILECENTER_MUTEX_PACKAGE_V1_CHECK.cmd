@echo off
py -3.12 -I -B "%~dp0host\filecenter_mutex_package_v1_check.py" %*
exit /b %errorlevel%
