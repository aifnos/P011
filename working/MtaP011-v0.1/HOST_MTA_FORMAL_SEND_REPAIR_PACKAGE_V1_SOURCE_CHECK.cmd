@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only; no ADB, stage, UI, wireless, phone or old tests.
py -3.12 -I -B "host\formal_send_repair_package_v1_source_check.py" %*
exit /b %errorlevel%
