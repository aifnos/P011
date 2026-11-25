@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only. Does not touch the P011.
py -3.12 -I -B "host\device_receive_filecenter_v1_startup_check.py" %*
exit /b %errorlevel%
