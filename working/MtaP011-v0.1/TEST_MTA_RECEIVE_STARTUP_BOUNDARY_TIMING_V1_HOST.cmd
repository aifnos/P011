@echo off
setlocal
cd /d "%~dp0"
rem One affected HOST method only; no graph, device or radio action.
py -3.12 -I -B "host\receive_startup_boundary_timing_v1_host_check.py" --run-host %*
exit /b %errorlevel%
