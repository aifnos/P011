@echo off
setlocal
cd /d "%~dp0"
rem ROOT only after real fresh core75 preparation; no automatic RF or input.
py -3.12 -I -B "host\device_formal_receive_startup_anchor_clock_ui_v1_check.py" --ui-smoke %*
exit /b %errorlevel%
