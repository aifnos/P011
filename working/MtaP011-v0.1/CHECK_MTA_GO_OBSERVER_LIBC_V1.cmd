@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\device_go_observer_libc_v1_check.py" %*
set "MTA_OBSERVER_LIBC_V1_EXIT=%ERRORLEVEL%"
echo CHECK_MTA_GO_OBSERVER_LIBC_V1_EXIT=%MTA_OBSERVER_LIBC_V1_EXIT%
exit /b %MTA_OBSERVER_LIBC_V1_EXIT%
