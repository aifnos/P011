@echo off
setlocal
cd /d "%~dp0"
rem PC-only affected parser contract and immutable recorded-device receipt.
py -3.12 -I -B "host\receive_navigation_vendor_frame_v1_host_check.py" %*
exit /b %errorlevel%
