@echo off
py -3.12 -I -B "%~dp0host\device_receive_profile_proc_dispatch_bench_v1_check.py"
exit /b %errorlevel%
