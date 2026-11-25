@echo off
setlocal
rem PC SOURCE by default; only --check-device opens one authorized discovery window.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_phone_discovery_v1_check.py" %*
exit /b %errorlevel%
