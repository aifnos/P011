@echo off
py -3.12 -I -B "%~dp0host\receive_handoff_terminal_v1_check.py" --check-host
exit /b %errorlevel%
