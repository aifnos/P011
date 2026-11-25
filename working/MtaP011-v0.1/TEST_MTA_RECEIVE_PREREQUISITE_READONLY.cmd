@echo off
setlocal
cd /d "%~dp0"
py -3.12 -E -B "host\device_receive_prerequisite_20261004.py" --check-readonly
exit /b %errorlevel%
