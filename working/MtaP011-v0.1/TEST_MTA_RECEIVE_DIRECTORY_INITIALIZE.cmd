@echo off
cd /d "%~dp0"
py -3 -B host\device_receive_directory_initialize.py --initialize-received
exit /b %errorlevel%
