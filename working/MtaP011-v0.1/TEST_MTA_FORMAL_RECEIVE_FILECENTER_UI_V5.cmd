@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: fixed20s UI, bounded failure projection, no automatic RF/input.
rem Original caps and recovery gates; never retry an existing CONTROL.
py -3.12 -I -B "host\device_formal_receive_filecenter_ui_v5_check.py" --ui-smoke %*
exit /b %errorlevel%
