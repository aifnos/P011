@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only; Owner path normalization diagnostic, no old tests or device.
py -3.12 -I -B "host\formal_send_repair_package_v2_source_check.py" %*
exit /b %errorlevel%
