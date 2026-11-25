@echo off
setlocal
rem SOURCE only. No business, old tests, WSL or device arguments.
cd /d "%~dp0"
py -3.12 -I -B "host\formal_send_filecenter_source_check.py"
set "MTA_SEND_FILECENTER_SOURCE_EXIT=%ERRORLEVEL%"
echo HOST_MTA_FORMAL_SEND_FILECENTER_SOURCE_EXIT=%MTA_SEND_FILECENTER_SOURCE_EXIT%
exit /b %MTA_SEND_FILECENTER_SOURCE_EXIT%
