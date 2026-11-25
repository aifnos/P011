@echo off
setlocal
cd /d "%~dp0"
rem Default SOURCE only. A sealed new isolated graph is required.
py -3.12 -I -B "host\device_receive_startup_anchor_clock_v1_check.py" %*
exit /b %errorlevel%
