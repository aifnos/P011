@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\device_formal_send_filecenter_ui_v3_check.py" %*
set "MTA_SEND_UI_V3_EXIT=%ERRORLEVEL%"
echo TEST_MTA_FORMAL_SEND_FILECENTER_UI_V3_EXIT=%MTA_SEND_UI_V3_EXIT%
exit /b %MTA_SEND_UI_V3_EXIT%
