@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: one fixed20s UI attempt and five original boundary diagnostics.
rem No automatic RF, input, phone; original true600+60/46facts/closure.
py -3.12 -I -B "host\device_formal_receive_startup_boundary_timing_ui_v1_check.py" --ui-smoke %*
exit /b %errorlevel%
