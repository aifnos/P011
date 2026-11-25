@echo off
setlocal
rem Default PC SOURCE only. Interactive UI requires explicit --check-device --ui.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_interactive_v1_check.py" %*
exit /b %errorlevel%
