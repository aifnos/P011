@echo off
setlocal
rem ROOT executes only the new duration DATA contract. No device/native actions.
cd /d "%~dp0"
py -3.12 -I -B "tests\test_receive_phone_discovery_120s_v1.py"
exit /b %errorlevel%
