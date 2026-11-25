@echo off
setlocal
cd /d "%~dp0"
rem Explicit one empty CLIENT root mkdir only, after fresh strict gates. No RF.
py -3.12 -I -B "host\device_prepare_empty_client_root_v1.py" --prepare-device
exit /b %errorlevel%
