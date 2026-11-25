@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\receive_filecenter_audio_loading_check.py"
set "MTA_AUDIO_LOADING_EXIT=%ERRORLEVEL%"
echo HOST_MTA_RECEIVE_AUDIO_LOADING_EXIT=%MTA_AUDIO_LOADING_EXIT%
exit /b %MTA_AUDIO_LOADING_EXIT%
