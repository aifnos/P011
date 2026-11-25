@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_ble_diagnostic_20261004.py" --capabilities-readonly
exit /b %errorlevel%
