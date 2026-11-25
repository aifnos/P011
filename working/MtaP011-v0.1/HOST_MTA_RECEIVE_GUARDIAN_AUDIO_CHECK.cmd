@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\receive_filecenter_guardian_audio_check.py"
set "MTA_GUARDIAN_AUDIO_EXIT=%ERRORLEVEL%"
echo HOST_MTA_RECEIVE_GUARDIAN_AUDIO_EXIT=%MTA_GUARDIAN_AUDIO_EXIT%
exit /b %MTA_GUARDIAN_AUDIO_EXIT%
