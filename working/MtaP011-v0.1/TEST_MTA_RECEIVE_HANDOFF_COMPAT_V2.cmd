@echo off
setlocal
rem Explicit headless phone window with the independent v2 startup-root closure.
rem No accept/send/UI. Original cancellation, closure and pending remain strict.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_handoff_compat_v2_check.py" --check-device %*
exit /b %errorlevel%
