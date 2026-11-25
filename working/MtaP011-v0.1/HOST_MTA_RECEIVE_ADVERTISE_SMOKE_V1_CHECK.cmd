@echo off
setlocal
rem Default PC SOURCE. Pass --check-device only for the authorized real receive advert/cancel.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_advertise_smoke_v1_check.py" %*
exit /b %errorlevel%
