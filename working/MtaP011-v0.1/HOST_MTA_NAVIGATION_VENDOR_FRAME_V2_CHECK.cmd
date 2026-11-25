@echo off
setlocal
cd /d "%~dp0"
rem PC-only strict raw envelope contract and immutable recorded-device receipt.
py -3.12 -I -B "host\receive_navigation_vendor_frame_v2_host_check.py" %*
exit /b %errorlevel%
