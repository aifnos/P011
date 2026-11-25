@echo off
cd /d "%~dp0"
py -3.12 -I -B host\receive_directory_adapters_source_check.py
exit /b %errorlevel%
