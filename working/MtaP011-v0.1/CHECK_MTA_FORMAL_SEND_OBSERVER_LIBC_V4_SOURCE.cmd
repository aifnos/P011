@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\formal_send_observer_libc_v4_source_check.py" %*
set "MTA_V4_SOURCE_EXIT=%ERRORLEVEL%"
echo CHECK_MTA_FORMAL_SEND_OBSERVER_LIBC_V4_SOURCE_EXIT=%MTA_V4_SOURCE_EXIT%
exit /b %MTA_V4_SOURCE_EXIT%
