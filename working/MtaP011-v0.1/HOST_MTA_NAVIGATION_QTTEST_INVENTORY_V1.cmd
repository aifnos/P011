@echo off
cd /d "%~dp0"
py -3.12 -I -B host\device_navigation_qttest_inventory_v1_check.py
pause
