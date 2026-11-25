@echo off
setlocal
cd /d "%~dp0"
rem SOURCE default: post-cleanup Startup expiry projection, no device.
py -3.12 -I -B "host\device_formal_receive_filecenter_ui_v5_check.py" %*
exit /b %errorlevel%
