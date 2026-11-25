@echo off
setlocal
rem Default PC SOURCE; --derive-existing reads the first FAIL; --check-device is startup/close only.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_advertise_smoke_v2_diagnostic.py" %*
exit /b %errorlevel%
