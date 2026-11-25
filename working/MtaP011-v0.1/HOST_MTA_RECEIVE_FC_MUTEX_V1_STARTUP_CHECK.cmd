@echo off
py -3.12 -I -B "%~dp0host\device_receive_fc_mutex_v1_startup_check.py"
exit /b %errorlevel%
