@echo off
setlocal
rem Default PC SOURCE only. Device and UI require explicit --check-device / --ui.
cd /d "%~dp0"
py -3.12 -I -B "host\device_formal_receive_v3_check.py" %*
exit /b %errorlevel%

