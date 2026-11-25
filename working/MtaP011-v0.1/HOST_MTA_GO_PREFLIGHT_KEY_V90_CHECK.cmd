@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "%~dp0host\go_preflight_key_v90_check.py"
set "p011_host_exit=%errorlevel%"
echo HOST-only result exit: %p011_host_exit%
pause
exit /b %p011_host_exit%
