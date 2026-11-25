@echo off
setlocal
rem Explicit original phone discovery plus finite diagnostic trace. No accept/send/UI.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_handoff_trace_v1_check.py" --check-device %*
exit /b %errorlevel%
