@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\device_go_readonly_native_v1_check.py"
set "MTA_GO_READONLY_NATIVE_V1_EXIT=%ERRORLEVEL%"
echo HOST_MTA_GO_READONLY_NATIVE_V1_SOURCE_CHECK_EXIT=%MTA_GO_READONLY_NATIVE_V1_EXIT%
exit /b %MTA_GO_READONLY_NATIVE_V1_EXIT%
