@echo off
cd /d "%~dp0"
python -B host\preview_mta_ui.py --interactive
pause
