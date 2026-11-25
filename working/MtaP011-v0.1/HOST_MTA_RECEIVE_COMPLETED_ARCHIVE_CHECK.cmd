@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\receive_completed_archive_host_check.py"
set "MTA_RECEIVE_ARCHIVE_EXIT=%ERRORLEVEL%"
echo HOST_MTA_RECEIVE_COMPLETED_ARCHIVE_EXIT=%MTA_RECEIVE_ARCHIVE_EXIT%
exit /b %MTA_RECEIVE_ARCHIVE_EXIT%
