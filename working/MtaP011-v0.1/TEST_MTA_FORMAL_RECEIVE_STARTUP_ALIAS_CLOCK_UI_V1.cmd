@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: fixed20s startupfix UI, no automatic RF/input/phone.
rem Same frozen GUI19, true600+60 Receiver and original restoration gates.
py -3.12 -I -B "host\device_formal_receive_startup_alias_clock_ui_v1_check.py" --ui-smoke %*
exit /b %errorlevel%
