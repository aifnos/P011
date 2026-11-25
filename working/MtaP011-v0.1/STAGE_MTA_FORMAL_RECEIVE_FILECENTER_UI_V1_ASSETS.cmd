@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: exclusive fixed GUI files/readback. No Owner/UI/RF/credentials.
py -3.12 -I -B "host\device_formal_receive_filecenter_ui_v1_check.py" --stage-device %*
exit /b %errorlevel%
