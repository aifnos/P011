@echo off
setlocal
cd /d "%~dp0"
rem PC-only one affected status HOST fixture; no full State/graph/device/phone.
py -3.12 -I -B "host\formal_send_cancel_status_v1_host_check.py" %*
exit /b %errorlevel%
