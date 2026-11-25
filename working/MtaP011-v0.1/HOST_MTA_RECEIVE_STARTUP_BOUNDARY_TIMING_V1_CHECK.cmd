@echo off
setlocal
cd /d "%~dp0"
rem Default SOURCE only; no device, RF or old graph/main execution.
py -3.12 -I -B "host\device_receive_startup_boundary_timing_v1_check.py" %*
exit /b %errorlevel%
