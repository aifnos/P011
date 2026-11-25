@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\device_formal_send_filecenter_ui_v2_check.py" %*
set "MTA_SEND_UI_V2_EXIT=%ERRORLEVEL%"
echo TEST_MTA_FORMAL_SEND_FILECENTER_UI_V2_EXIT=%MTA_SEND_UI_V2_EXIT%
exit /b %MTA_SEND_UI_V2_EXIT%
