@echo off
setlocal
cd /d "%~dp0"
rem Exactly one new affected HOST contract, no old suite, graph or ADB.
py -3.12 -I -B "host\receive_startup_anchor_clock_v1_host_check.py" --run-host %*
exit /b %errorlevel%
