@echo off
setlocal
cd /d "%~dp0"
rem One affected HOST Proc method only. No ADB, RF or previous test suite.
py -3.12 -I -B "host\receive_proc_freezer_v2_host_check.py" --run-host %*
exit /b %errorlevel%
