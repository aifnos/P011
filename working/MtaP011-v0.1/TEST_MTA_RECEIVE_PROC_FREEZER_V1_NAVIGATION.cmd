@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B host\device_receive_proc_freezer_v1_navigation_check.py --navigation-test
exit /b %errorlevel%
