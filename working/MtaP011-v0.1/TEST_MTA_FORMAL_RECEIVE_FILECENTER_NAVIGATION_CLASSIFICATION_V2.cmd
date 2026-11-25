@echo off
setlocal
cd /d "%~dp0"
rem ROOT only: classification optimization with unchanged navigation diagnosis; no automatic RF.
py -3.12 -I -B "host\device_formal_receive_filecenter_navigation_classification_v2_check.py" --navigation-test %*
exit /b %errorlevel%
