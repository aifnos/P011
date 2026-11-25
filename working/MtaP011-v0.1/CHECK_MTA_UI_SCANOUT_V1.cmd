@echo off
setlocal
rem PC SOURCE by default. Use --check-device for private read-only P011 scanout.
cd /d "%~dp0"
py -3.12 -I -B "host\capture_ui_scanout_v1.py" %*
exit /b %errorlevel%
