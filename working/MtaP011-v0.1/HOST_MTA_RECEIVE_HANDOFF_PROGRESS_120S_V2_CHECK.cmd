@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only. New passive stage fields; no tests/ADB/device/old graph.
py -3.12 -I -B "host\device_receive_handoff_progress_120s_v2_check.py" %*
exit /b %errorlevel%
