@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B host\receive_durable_gui_v1_pc_check.py --build
exit /b %errorlevel%
