@echo off
setlocal
rem Default PC SOURCE only. Explicit --read-device reads four fixed metadata files.
cd /d "%~dp0"
py -3.12 -I -B "host\device_client_source_metadata_readonly_v1_check.py" %*
exit /b %errorlevel%
