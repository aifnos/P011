@echo off
setlocal
rem Default PC SOURCE only. No device or archive policy is selected by this command.
cd /d "%~dp0..\..\.."
py -3.12 -I -B "host\device_receive_completed_archive_integrated_v1_check.py" %*
exit /b %errorlevel%
