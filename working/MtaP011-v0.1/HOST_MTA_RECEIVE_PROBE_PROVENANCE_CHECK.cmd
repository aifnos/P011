@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B host\receive_probe_provenance_check.py
set "mta_probe_exit=%ERRORLEVEL%"
echo HOST only. No ADB, RF, or phone operations.
pause
exit /b %mta_probe_exit%
