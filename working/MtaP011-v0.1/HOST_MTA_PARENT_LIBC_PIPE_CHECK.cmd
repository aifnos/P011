@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\parent_libc_pipe_check.py"
exit /b %ERRORLEVEL%
