@echo off
setlocal
rem PC SOURCE by default. Explicit --check-device requires the actual test authority.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_handoff_trace_v1_check.py" %*
exit /b %errorlevel%
