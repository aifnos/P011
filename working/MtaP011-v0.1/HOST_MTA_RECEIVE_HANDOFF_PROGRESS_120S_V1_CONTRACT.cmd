@echo off
setlocal
rem ROOT executes only one changed observer DATA contract. No device/native actions.
cd /d "%~dp0"
py -3.12 -I -B "tests\test_receive_handoff_progress_120s_v1.py"
exit /b %errorlevel%
