@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\test_ready_capture_stream_v1.py" --check-host
set "MTA_STREAM_HOST_EXIT=%ERRORLEVEL%"
echo CHECK_MTA_READY_CAPTURE_STREAM_V1_HOST_EXIT=%MTA_STREAM_HOST_EXIT%
exit /b %MTA_STREAM_HOST_EXIT%
