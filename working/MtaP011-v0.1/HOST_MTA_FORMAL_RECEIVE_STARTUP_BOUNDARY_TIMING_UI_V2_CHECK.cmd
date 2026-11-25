@echo off
setlocal
cd /d "%~dp0"
rem Default SOURCE only; new exclusive CONTROL, same pinned timing graph.
py -3.12 -I -B "host\device_formal_receive_startup_boundary_timing_ui_v2_check.py" %*
exit /b %errorlevel%
