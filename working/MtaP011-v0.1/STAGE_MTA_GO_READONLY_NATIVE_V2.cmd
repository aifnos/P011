@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\device_go_readonly_native_v2_check.py" --stage-native
set "MTA_GO_READONLY_NATIVE_V2_EXIT=%ERRORLEVEL%"
echo STAGE_MTA_GO_READONLY_NATIVE_V2_EXIT=%MTA_GO_READONLY_NATIVE_V2_EXIT%
exit /b %MTA_GO_READONLY_NATIVE_V2_EXIT%
