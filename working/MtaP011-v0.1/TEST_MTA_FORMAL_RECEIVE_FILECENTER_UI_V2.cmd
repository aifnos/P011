@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: unchanged Receiver/FC; isolated log root, no parallel target observer.
py -3.12 -I -B "host\device_formal_receive_filecenter_ui_v2_check.py" --ui-smoke %*
exit /b %errorlevel%
