@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\receive_completed_archive_startup_source_check.py"
set "MTA_RECEIVE_ARCHIVE_SOURCE_EXIT=%ERRORLEVEL%"
echo HOST_MTA_RECEIVE_COMPLETED_ARCHIVE_SOURCE_EXIT=%MTA_RECEIVE_ARCHIVE_SOURCE_EXIT%
exit /b %MTA_RECEIVE_ARCHIVE_SOURCE_EXIT%
