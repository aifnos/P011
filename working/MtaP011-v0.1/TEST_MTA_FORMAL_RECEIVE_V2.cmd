@echo off
setlocal
rem Explicit closed-gate device graph check; optional --ui selects fixed copied UI.
cd /d "%~dp0"
py -3.12 -I -B "host\device_formal_receive_v2_check.py" --check-device %*
exit /b %errorlevel%
