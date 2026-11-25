@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\receive_filecenter_partial_resource_check.py"
set "MTA_PARTIAL_RESOURCE_EXIT=%ERRORLEVEL%"
echo HOST_MTA_RECEIVE_PARTIAL_RESOURCE_EXIT=%MTA_PARTIAL_RESOURCE_EXIT%
exit /b %MTA_PARTIAL_RESOURCE_EXIT%
