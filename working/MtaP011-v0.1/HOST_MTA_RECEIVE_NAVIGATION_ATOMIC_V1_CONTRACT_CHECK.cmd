@echo off
setlocal
cd /d "%~dp0"
rem Only one affected HOST transition contract. No ADB, RF or old suite.
py -3.12 -I -B "host\receive_navigation_atomic_v1_host_check.py" --run-host %*
exit /b %errorlevel%
