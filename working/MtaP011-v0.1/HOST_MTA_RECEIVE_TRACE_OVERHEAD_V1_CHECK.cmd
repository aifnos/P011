@echo off
py -3.12 -I -B "%~dp0host\receive_trace_overhead_v1_check.py"
exit /b %errorlevel%
