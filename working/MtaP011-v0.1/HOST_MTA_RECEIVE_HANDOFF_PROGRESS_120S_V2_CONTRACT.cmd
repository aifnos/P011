@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: one new pure DATA stage contract, no old suite/device/native proof.
py -3.12 -I -B "tests\test_receive_handoff_progress_120s_v2.py"
exit /b %errorlevel%
