@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\device_parent_libc_pipe_check.py" --check-device
exit /b %errorlevel%
