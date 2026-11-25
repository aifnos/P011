@echo off
setlocal
rem PC SOURCE only. No old graph/suite/ADB/radio action.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_handoff_progress_120s_v1_check.py" %*
exit /b %errorlevel%
