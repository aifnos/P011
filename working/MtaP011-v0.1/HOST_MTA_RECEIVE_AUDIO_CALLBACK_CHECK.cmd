@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\receive_filecenter_audio_callback_check.py"
set "MTA_AUDIO_CALLBACK_EXIT=%ERRORLEVEL%"
echo HOST_MTA_RECEIVE_AUDIO_CALLBACK_EXIT=%MTA_AUDIO_CALLBACK_EXIT%
exit /b %MTA_AUDIO_CALLBACK_EXIT%
