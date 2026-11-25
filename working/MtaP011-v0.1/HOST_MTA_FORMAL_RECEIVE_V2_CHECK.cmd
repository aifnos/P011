@echo off
setlocal
rem Default PC SOURCE graph check only. No old START or device access.
cd /d "%~dp0"
py -3.12 -I -B "host\device_formal_receive_v2_check.py" %*
exit /b %errorlevel%
