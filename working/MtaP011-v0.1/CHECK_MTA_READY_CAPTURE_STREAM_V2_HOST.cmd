@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\test_ready_capture_stream_v2.py" --check-host
set "MTA_STREAM_V2_HOST_EXIT=%ERRORLEVEL%"
echo CHECK_MTA_READY_CAPTURE_STREAM_V2_HOST_EXIT=%MTA_STREAM_V2_HOST_EXIT%
exit /b %MTA_STREAM_V2_HOST_EXIT%
