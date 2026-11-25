@echo off
setlocal
cd /d "%~dp0"
rem ROOT explicit120s phone/peer15s, may real Parent Wi-Fi initialize; no accept/send/file/UI.
py -3.12 -I -B "host\device_receive_alias_clock_v1_check.py" --check-device %*
exit /b %errorlevel%
