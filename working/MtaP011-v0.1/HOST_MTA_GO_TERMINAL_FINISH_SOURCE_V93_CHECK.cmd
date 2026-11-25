@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\go_terminal_finish_source_v93_check.py"
set "p011_host_exit=%errorlevel%"
echo HOST-only F/Bridge93 finish DATA check exited %p011_host_exit%.
pause
exit /b %p011_host_exit%
