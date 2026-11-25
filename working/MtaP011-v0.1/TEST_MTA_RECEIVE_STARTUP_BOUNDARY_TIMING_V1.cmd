@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: new graph75 stage and original diagnostic startup/close.
rem No FileCenter companion/credentials/UI/RF/phone/transfer.
py -3.12 -I -B "host\device_receive_startup_boundary_timing_v1_check.py" --check-device %*
exit /b %errorlevel%
