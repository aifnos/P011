@echo off
cd /d "%~dp0"
py -B host\platform_v13_source_check.py
exit /b %errorlevel%
