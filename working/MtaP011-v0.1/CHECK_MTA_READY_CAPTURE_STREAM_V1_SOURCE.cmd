@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\test_ready_capture_stream_v1.py"
set "MTA_STREAM_SOURCE_EXIT=%ERRORLEVEL%"
echo CHECK_MTA_READY_CAPTURE_STREAM_V1_SOURCE_EXIT=%MTA_STREAM_SOURCE_EXIT%
exit /b %MTA_STREAM_SOURCE_EXIT%
