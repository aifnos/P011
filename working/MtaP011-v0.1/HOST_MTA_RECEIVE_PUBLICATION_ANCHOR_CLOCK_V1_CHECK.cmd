@echo off
setlocal
cd /d "%~dp0"
rem One fixed affected HOST contract with private logs and public ZIP; no device.
py -3.12 -I -B "host\receive_publication_anchor_clock_v1_host_check.py" --run-host %*
exit /b %errorlevel%
