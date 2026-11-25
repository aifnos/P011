@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: true Receiver600+60 with FileCenter, launched+20s idle; no auto RF/audio.
py -3.12 -I -B "host\device_formal_receive_filecenter_ui_v1_check.py" --ui-smoke %*
exit /b %errorlevel%
