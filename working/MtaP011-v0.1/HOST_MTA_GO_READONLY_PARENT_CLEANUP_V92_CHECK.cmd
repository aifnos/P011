@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\go_readonly_parent_cleanup_v92_check.py"
set "p011_host_exit=%errorlevel%"
echo HOST-only Parent92 cleanup check exited %p011_host_exit%.
pause
exit /b %p011_host_exit%
