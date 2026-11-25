@echo off
setlocal
rem ROOT runs only two new affected HOST tests. No device/old graph/suite.
cd /d "%~dp0"
py -3.12 -I -B "tests\test_receive_handoff_compat_v2.py"
exit /b %errorlevel%
