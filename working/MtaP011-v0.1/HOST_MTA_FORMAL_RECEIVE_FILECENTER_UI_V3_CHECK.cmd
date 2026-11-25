@echo off
setlocal
cd /d "%~dp0"
rem PC SOURCE only; credential-chain fix, no pen or screenshot observer.
py -3.12 -I -B "host\device_formal_receive_filecenter_ui_v3_check.py" %*
exit /b %errorlevel%
