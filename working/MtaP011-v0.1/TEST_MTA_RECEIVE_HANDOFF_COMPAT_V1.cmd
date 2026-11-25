@echo off
setlocal
rem Explicit headless phone window with the independent compatibility graph.
rem No accept/send/UI. Original cancellation, closure and pending remain strict.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_handoff_compat_v1_check.py" --check-device %*
exit /b %errorlevel%
