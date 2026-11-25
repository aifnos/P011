@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only, new6 exact alias clock/root/pin derivation. No HOST test/device.
py -3.12 -I -B "host\device_receive_alias_clock_v1_check.py" %*
exit /b %errorlevel%
