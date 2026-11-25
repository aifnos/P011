@echo off
setlocal
rem Default PC SOURCE only. Explicit --read-device is fixed-root readonly diagnosis.
cd /d "%~dp0"
py -3.12 -I -B "host\device_client_history_readonly_v1_check.py" %*
exit /b %errorlevel%
