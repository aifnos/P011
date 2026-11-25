@echo off
py -3.12 -I -B "%~dp0host\device_formal_send_fc_mutex_service_v1_check.py" --check-device
exit /b %errorlevel%
