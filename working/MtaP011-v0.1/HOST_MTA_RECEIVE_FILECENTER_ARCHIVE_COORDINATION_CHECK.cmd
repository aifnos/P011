@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\receive_filecenter_archive_coordination_host_check.py"
set "MTA_RECEIVE_ARCHIVE_COORD_EXIT=%ERRORLEVEL%"
echo HOST_MTA_RECEIVE_ARCHIVE_COORD_EXIT=%MTA_RECEIVE_ARCHIVE_COORD_EXIT%
exit /b %MTA_RECEIVE_ARCHIVE_COORD_EXIT%
