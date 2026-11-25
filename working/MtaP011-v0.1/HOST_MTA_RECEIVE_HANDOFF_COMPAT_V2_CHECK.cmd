@echo off
setlocal
rem PC SOURCE only by default. No graph execution, ADB or radio action.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_handoff_compat_v2_check.py" %*
exit /b %errorlevel%
