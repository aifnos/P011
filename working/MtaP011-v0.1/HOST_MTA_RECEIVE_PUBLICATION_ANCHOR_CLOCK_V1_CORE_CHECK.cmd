@echo off
setlocal
cd /d "%~dp0"
rem Default SOURCE only. New graph definitions must first be sealed by ROOT.
py -3.12 -I -B "host\device_receive_publication_anchor_clock_v1_check.py" %*
exit /b %errorlevel%
