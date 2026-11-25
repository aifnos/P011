@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only: exact False diagnostic envelope. No old graph/test/device.
py -3.12 -I -B "host\device_receive_alias_clock_startup_v1_check.py" %*
exit /b %errorlevel%
