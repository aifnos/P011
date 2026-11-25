@echo off
setlocal
rem Explicit phone discovery only; real ready notice, no accept/send/UI.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_phone_discovery_v1_check.py" --check-device %*
exit /b %errorlevel%
