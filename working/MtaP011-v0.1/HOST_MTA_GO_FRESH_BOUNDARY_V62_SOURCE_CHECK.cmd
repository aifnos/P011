@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 exit /b 1
rem PC SOURCE only. No device or RF trial. Do not rerun just to obtain logs.
py -3 -I -B host\go_fresh_boundary_v62_p011.py
exit /b %errorlevel%
