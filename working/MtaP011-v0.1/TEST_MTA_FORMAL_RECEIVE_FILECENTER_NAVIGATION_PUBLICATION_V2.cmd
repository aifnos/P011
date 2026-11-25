@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: actual QtTest Item click and Received listing; after-run INNER/PROC only.
py -3.12 -I -B "host\device_formal_receive_filecenter_navigation_publication_v2_check.py" --navigation-test %*
exit /b %errorlevel%
