@echo off
setlocal
cd /d "%~dp0"
rem ROOT explicit new CONTROL; unchanged device navigation and strict HOST log parser. No automatic RF.
py -3.12 -I -B "host\device_formal_receive_filecenter_navigation_classification_v3_check.py" --navigation-test %*
exit /b %errorlevel%
