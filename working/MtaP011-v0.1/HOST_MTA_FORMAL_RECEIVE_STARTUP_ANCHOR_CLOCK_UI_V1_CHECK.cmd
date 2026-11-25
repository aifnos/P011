@echo off
setlocal
cd /d "%~dp0"
rem SOURCE only. All fresh graph, Worker and diagnostic pins must be sealed.
py -3.12 -I -B "host\device_formal_receive_startup_anchor_clock_ui_v1_check.py" %*
exit /b %errorlevel%
