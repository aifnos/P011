@echo off
setlocal
rem --install-private-assets installs fixed files only; never starts receive.
cd /d "%~dp0"
py -3.12 -I -B "host\device_closed_service_check.py" --check-device %*
exit /b %errorlevel%
