@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: actual navigation with cached refusal DATA; no automatic RF.
py -3.12 -I -B "host\device_formal_receive_filecenter_navigation_publication_v3_check.py" --navigation-test %*
exit /b %errorlevel%
