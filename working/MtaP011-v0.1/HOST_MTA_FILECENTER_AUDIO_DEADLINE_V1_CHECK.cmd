@echo off
cd /d "%~dp0"
py -3.12 -B host\device_filecenter_audio_deadline_v1_check.py
exit /b %errorlevel%
