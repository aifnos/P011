@echo off
setlocal
cd /d "%~dp0"
rem Default SOURCE only; no graph target, device, RF or old main execution.
py -3.12 -I -B "host\device_formal_receive_startup_boundary_timing_ui_v1_check.py" %*
exit /b %errorlevel%
