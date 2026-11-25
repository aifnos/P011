@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only unless an explicit device argument is supplied.
py -3.12 -I -B "host\device_receive_profile_classification_clock_v1_check.py" %*
exit /b %errorlevel%
