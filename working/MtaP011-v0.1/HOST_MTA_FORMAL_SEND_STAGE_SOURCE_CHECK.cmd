@echo off
cd /d "%~dp0"
py -3.12 -I -B host\formal_send_stage_source_check.py
exit /b %errorlevel%
