@echo off
cd /d "%~dp0"
py -3.12 -I -B host\client_wpa_comm_no_fd_v26_check.py
exit /b %errorlevel%
