@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: actual launched+20s UI with read-only capture after real READY.
rem No automatic RF, file opening, audio or input; original recovery gates.
py -3.12 -I -B "host\device_formal_receive_filecenter_ui_v4_check.py" --ui-smoke %*
exit /b %errorlevel%
