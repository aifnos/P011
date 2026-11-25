@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "%~dp0host\go_readonly_owner_v89_check.py"
set "p011_host_exit=%errorlevel%"
echo HOST-only result exit: %p011_host_exit%
pause
exit /b %p011_host_exit%
