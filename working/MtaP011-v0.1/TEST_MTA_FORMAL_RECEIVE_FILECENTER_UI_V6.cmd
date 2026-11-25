@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: fixed20s UI with after-cleanup bounded Proc diagnostic.
rem No automatic RF/input, unchanged original recovery, no old CONTROL retry.
py -3.12 -I -B "host\device_formal_receive_filecenter_ui_v6_check.py" --ui-smoke %*
exit /b %errorlevel%
