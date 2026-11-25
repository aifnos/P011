@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\go_send_fixed_boot_v91_check.py"
set "p011_host_exit=%errorlevel%"
echo HOST-only fixed Boot91 check exited %p011_host_exit%.
pause
exit /b %p011_host_exit%
