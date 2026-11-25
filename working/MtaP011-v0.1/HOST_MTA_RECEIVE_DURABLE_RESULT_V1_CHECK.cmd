@echo off
setlocal
cd /d "%~dp0"
rem PC WSL only. No ADB, wireless window or device deployment.
py -3.12 -B host\receive_durable_result_v1_host_check.py
set "task_exit=%errorlevel%"
echo HOST exit: %task_exit%
pause
exit /b %task_exit%
