@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B host\device_receive_navigation_frame_v2_check.py
exit /b %errorlevel%
