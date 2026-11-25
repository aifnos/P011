@echo off
setlocal
cd /d "%~dp0"
rem Default SOURCE only; no graph/worker target execution or device action.
py -3.12 -I -B "host\device_formal_receive_startup_alias_clock_ui_v1_check.py" %*
exit /b %errorlevel%
