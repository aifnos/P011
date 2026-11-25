@echo off
py -3.12 -I -B "%~dp0host\session_absolute_v78_check.py"
exit /b %errorlevel%
