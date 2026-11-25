@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only; no pen or screenshot observer.
py -3.12 -I -B "host\device_formal_receive_filecenter_ui_v2_check.py" %*
exit /b %errorlevel%
