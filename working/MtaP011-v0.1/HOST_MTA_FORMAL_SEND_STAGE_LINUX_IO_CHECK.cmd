@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\formal_send_stage_linux_io_host_check.py"
set "MTA_SEND_STAGE_LINUX_IO_EXIT=%ERRORLEVEL%"
echo HOST_MTA_FORMAL_SEND_STAGE_LINUX_IO_EXIT=%MTA_SEND_STAGE_LINUX_IO_EXIT%
exit /b %MTA_SEND_STAGE_LINUX_IO_EXIT%
