@echo off
setlocal
cd /d "%~dp0"
py -3 -I -B host\device_receive_filecenter_assets_v1_check.py %*
exit /b %errorlevel%
