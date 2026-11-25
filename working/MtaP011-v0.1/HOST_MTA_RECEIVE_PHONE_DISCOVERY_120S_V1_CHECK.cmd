@echo off
setlocal
rem PC SOURCE only. No graph/old suite/ADB/radio action.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_phone_discovery_120s_v1_check.py" %*
exit /b %errorlevel%
