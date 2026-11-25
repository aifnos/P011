@echo off
setlocal
rem Explicit real receive advertisement test. Never Qt takeover, pair, accept or send.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_advertise_smoke_v1_check.py" --check-device %*
exit /b %errorlevel%
