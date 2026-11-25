@echo off
cd /d "%~dp0"
py -3.12 -B host\formal_receive_terminal_check.py %*
exit /b %errorlevel%
