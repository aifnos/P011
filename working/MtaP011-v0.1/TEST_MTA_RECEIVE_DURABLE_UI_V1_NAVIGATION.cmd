@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B host\device_formal_receive_durable_ui_v1_check.py --navigation-test
exit /b %errorlevel%
