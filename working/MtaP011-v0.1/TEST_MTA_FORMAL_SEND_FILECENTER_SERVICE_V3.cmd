@echo off
cd /d "%~dp0"
if "%~1"=="" goto local
if not "%~1"=="--check-device" exit /b 2
if not "%~2"=="" exit /b 2
py -3.12 -I -B host\device_formal_send_filecenter_service_v3_check.py --check-device
exit /b %errorlevel%
:local
py -3.12 -I -B host\device_formal_send_filecenter_service_v3_check.py
exit /b %errorlevel%
