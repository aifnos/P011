@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: fresh graph75 stage and original diagnostic startup-close.
rem No FileCenter companion, credentials, UI, RF, phone or transfer.
py -3.12 -I -B "host\device_receive_startup_anchor_clock_v1_check.py" --check-device %*
exit /b %errorlevel%
