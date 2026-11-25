@echo off
cd /d "%~dp0"
py -3.12 -I -B host\receive_navigation_gui_v1_pc_check.py --build
pause
