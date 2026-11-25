@echo off
setlocal
cd /d "%~dp0"
python -I -B host\device_client_source_archive_v1_check.py %*
set "MTA_ARCHIVE_EXIT=%ERRORLEVEL%"
echo MTA_CLIENT_SOURCE_ARCHIVE_CHECKER_EXIT=%MTA_ARCHIVE_EXIT%
exit /b %MTA_ARCHIVE_EXIT%
