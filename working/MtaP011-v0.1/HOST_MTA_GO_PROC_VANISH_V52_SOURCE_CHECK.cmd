@echo off
setlocal
cd /d "%~dp0"
python -B host\go_proc_vanish_v52_p011.py
exit /b %errorlevel%
