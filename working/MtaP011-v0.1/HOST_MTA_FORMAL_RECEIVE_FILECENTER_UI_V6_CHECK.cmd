@echo off
setlocal
cd /d "%~dp0"
rem Default SOURCE; no device or target projection execution.
py -3.12 -I -B "host\device_formal_receive_filecenter_ui_v6_check.py" %*
exit /b %errorlevel%
