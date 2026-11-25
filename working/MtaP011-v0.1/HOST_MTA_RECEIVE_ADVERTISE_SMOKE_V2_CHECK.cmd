@echo off
setlocal
rem Default PC SOURCE. Explicit --check-device invokes actual receive advertisement/cancel.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_advertise_smoke_v2_check.py" %*
exit /b %errorlevel%
