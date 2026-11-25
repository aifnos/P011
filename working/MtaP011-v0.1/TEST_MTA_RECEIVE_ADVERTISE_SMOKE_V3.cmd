@echo off
setlocal
rem Explicit actual one-shot receive advert/cancel; no UI, pairing, accept or send.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_advertise_smoke_v3_check.py" --check-device %*
exit /b %errorlevel%
