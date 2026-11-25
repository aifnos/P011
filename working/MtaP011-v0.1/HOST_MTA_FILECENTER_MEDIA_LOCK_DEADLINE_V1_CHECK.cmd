@echo off
py -3.12 -I -B "%~dp0host\filecenter_media_lock_deadline_v1_check.py" --run
exit /b %errorlevel%
