@echo off
cd /d "%~dp0"
python -B host\build_native.py --collect
pause
