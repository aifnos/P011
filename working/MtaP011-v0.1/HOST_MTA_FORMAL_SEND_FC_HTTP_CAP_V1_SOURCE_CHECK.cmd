@echo off
py -3.12 -I -B "%~dp0host\device_formal_send_fc_http_cap_v1_check.py"
exit /b %errorlevel%
