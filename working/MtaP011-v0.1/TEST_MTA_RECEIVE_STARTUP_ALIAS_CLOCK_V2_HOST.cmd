@echo off
setlocal
cd /d "%~dp0"
rem One fixed HOST method only; no P011, old suite or RF action.
py -3.12 -I -B "host\receive_startup_alias_clock_v2_host_check.py" --run-host
exit /b %errorlevel%
