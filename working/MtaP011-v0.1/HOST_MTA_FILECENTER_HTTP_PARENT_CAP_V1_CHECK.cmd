@echo off
py -3.12 -I -B "%~dp0host\filecenter_http_parent_cap_v1_check.py" --run
exit /b %errorlevel%
