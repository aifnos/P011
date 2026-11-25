@echo off
setlocal
cd /d "%~dp0"
rem One finite BLE component test; not a phone file receiver.
py -3.12 -I -B "host\device_receive_ble_diagnostic_20261004.py" --listen-advertise
exit /b %errorlevel%
