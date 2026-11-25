@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: exclusive GUI20 file-only stage; no Owner, UI or RF.
py -3.12 -I -B "host\device_formal_receive_filecenter_navigation_anchor_v1_check.py" --stage-device %*
exit /b %errorlevel%
