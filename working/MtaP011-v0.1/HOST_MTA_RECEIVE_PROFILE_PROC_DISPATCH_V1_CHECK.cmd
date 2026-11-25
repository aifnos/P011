@echo off
py -3.12 -I -B "%~dp0host\receive_profile_proc_dispatch_v1_host_check.py"
exit /b %errorlevel%
