@echo off
cd /d "%~dp0"
python -B host\device_probe.py
pause
