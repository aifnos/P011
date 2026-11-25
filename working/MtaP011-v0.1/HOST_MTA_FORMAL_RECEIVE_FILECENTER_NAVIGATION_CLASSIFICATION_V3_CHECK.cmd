@echo off
setlocal
cd /d "%~dp0"
rem Default PC SOURCE; strict observed vendor log parser. No automatic device.
py -3.12 -I -B "host\device_formal_receive_filecenter_navigation_classification_v3_check.py" %*
exit /b %errorlevel%
