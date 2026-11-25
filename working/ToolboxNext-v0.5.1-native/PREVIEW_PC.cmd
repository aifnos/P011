@echo off
cd /d "%~dp0"
python -B host\preview.py
if errorlevel 1 pause
