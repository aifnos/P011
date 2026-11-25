@echo off
setlocal
cd /d "%~dp0"
rem ROOT only after real core75 preparation, no automatic RF/input/phone.
py -3.12 -I -B "host\device_formal_receive_startup_boundary_timing_ui_v2_check.py" --ui-smoke %*
exit /b %errorlevel%
