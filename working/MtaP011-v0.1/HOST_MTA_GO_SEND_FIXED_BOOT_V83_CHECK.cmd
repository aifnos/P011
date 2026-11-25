@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B host\go_send_fixed_boot_v83_check.py
set "P011_MTA_EXIT=%ERRORLEVEL%"
echo.
echo HOST only: one new method, four affected fixed-Boot domains.
echo Filesystem, FD/EBADF, PID and clock are models, not P011 evidence.
echo No State, Server, helper, private CLIENT35 or GO24, RF or restore.
echo No device arguments, no candidate start, no pending deletion.
echo Result ZIP and failure private raw are retained in results.
pause
exit /b %P011_MTA_EXIT%
