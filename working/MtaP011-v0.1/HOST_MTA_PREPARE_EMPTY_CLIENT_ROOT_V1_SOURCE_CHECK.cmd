@echo off
setlocal
cd /d "%~dp0"
rem HOST-only SOURCE. No ADB, target write or radio.
py -3.12 -I -B "host\device_prepare_empty_client_root_v1.py"
exit /b %errorlevel%
