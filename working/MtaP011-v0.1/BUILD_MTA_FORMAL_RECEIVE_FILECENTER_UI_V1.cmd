@echo off
setlocal
cd /d "%~dp0"
rem PC-only immutable GUI build. No ADB, Docker, Owner, radio or credentials.
py -3.12 -I -B "host\build_formal_receive_filecenter_ui_v1.py" %*
exit /b %errorlevel%
