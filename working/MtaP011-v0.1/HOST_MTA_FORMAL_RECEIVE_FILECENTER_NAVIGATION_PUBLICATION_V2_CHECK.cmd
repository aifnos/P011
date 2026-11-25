@echo off
setlocal
cd /d "%~dp0"
rem Default PC SOURCE only; no pen operation without explicit mode.
py -3.12 -I -B "host\device_formal_receive_filecenter_navigation_publication_v2_check.py" %*
exit /b %errorlevel%
