@echo off
cd /d "%~dp0"
py -B host\client_connect_v14_source_check.py
exit /b %errorlevel%
