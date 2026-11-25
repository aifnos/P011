@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: actual QtTest Item click and Received listing, no RF or media.
py -3.12 -I -B "host\device_formal_receive_filecenter_navigation_publication_v1_check.py" --navigation-test %*
exit /b %errorlevel%
