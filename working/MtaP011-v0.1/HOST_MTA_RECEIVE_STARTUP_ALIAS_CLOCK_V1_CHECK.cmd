@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only. No P011 action. Requires ROOT-sealed fresh definition pin.
py -3.12 -I -B "host\device_receive_startup_alias_clock_v1_check.py" %*
exit /b %errorlevel%
