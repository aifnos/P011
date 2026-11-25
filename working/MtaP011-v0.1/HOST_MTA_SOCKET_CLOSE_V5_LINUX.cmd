@echo off
cd /d "%~dp0"
py -3.12 -I -B host\formal_socket_close_v5_linux_check.py %*
