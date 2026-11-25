@echo off
setlocal
cd /d "%~dp0"
py -3 -B host\device_receive_directory_readonly_20261004.py --read-current
exit /b %errorlevel%
