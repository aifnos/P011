@echo off
setlocal
cd /d "%~dp0"
rem SOURCE default: exact post-READY stream/capture composition, no device.
py -3.12 -I -B "host\device_formal_receive_filecenter_ui_v4_check.py" %*
exit /b %errorlevel%
