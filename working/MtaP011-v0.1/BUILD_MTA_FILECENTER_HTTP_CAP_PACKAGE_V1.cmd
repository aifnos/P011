@echo off
py -3.12 -I -B "%~dp0host\filecenter_http_cap_package_v1_check.py" --assemble
exit /b %errorlevel%
