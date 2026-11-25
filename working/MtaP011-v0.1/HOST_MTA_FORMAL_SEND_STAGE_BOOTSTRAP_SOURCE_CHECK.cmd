@echo off
setlocal
rem PC SOURCE only. No target/profile/transport arguments.
cd /d "%~dp0"
py -3.12 -I -B "host\formal_send_stage_bootstrap_source_check.py"
exit /b %errorlevel%
