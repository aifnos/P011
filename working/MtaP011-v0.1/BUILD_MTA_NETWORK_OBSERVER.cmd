@echo off
cd /d "%~dp0"
py -3.12 -B host\build_receive_network_observer.py %*
exit /b %errorlevel%
