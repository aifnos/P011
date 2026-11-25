@echo off
setlocal
rem Fixed copied UI plus startup-v4 observation. Default PC-only; --check-device is explicit.
cd /d "%~dp0"
py -3.12 -I -B "host\device_formal_ui_startup_v4_check.py" %*
exit /b %errorlevel%

