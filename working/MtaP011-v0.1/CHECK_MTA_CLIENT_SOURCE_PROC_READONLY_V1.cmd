@echo off
setlocal
rem Default PC SOURCE only. Explicit --read-device observes fixed-source proc collisions.
cd /d "%~dp0"
py -3.12 -I -B "host\device_client_source_proc_readonly_v1_check.py" %*
exit /b %errorlevel%
