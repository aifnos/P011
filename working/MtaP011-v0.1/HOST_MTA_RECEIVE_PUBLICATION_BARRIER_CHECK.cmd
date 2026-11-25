@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B host\receive_publication_barrier_check.py
set "mta_barrier_exit=%ERRORLEVEL%"
echo HOST Owner/IO/FD models only. No ADB, RF, or old record handling.
pause
exit /b %mta_barrier_exit%
