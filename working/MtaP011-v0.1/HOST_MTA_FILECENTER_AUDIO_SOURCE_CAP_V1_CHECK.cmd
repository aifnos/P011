@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B host\filecenter_audio_source_cap_v1_check.py --run
set "MTA_EXIT=%ERRORLEVEL%"
exit /b %MTA_EXIT%
