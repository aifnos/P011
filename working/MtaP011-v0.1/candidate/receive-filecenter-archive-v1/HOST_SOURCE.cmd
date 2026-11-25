@echo off
setlocal
rem PC SOURCE only. No device or browser policy arguments.
cd /d "%~dp0..\.."
py -3.12 -I -B "host\device_receive_filecenter_archive_v1_check.py"
exit /b %errorlevel%

