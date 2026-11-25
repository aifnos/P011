@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B host\device_receive_proc_identity_diff_v1_check.py --navigation-test
exit /b %errorlevel%
