@echo off
py -3.12 -I -B "%~dp0host\go_send_transport_v76_r5_check.py"
exit /b %errorlevel%
