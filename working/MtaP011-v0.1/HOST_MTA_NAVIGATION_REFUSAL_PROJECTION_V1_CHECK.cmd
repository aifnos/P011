@echo off
setlocal
cd /d "%~dp0"
rem Only the one affected HOST fixture method; never ADB.
py -3.12 -I -B "host\receive_navigation_refusal_projection_v1_host_check.py" --run-host %*
exit /b %errorlevel%
