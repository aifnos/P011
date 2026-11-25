@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only. Does not touch the pen.
py -3.12 -I -B "host\device_formal_receive_filecenter_ui_v1_check.py" %*
exit /b %errorlevel%
