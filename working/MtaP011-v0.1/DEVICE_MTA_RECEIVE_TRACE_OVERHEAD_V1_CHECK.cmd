@echo off
py -3.12 -I -B "%~dp0host\device_receive_trace_overhead_v1_check.py" --check-device
exit /b %errorlevel%
