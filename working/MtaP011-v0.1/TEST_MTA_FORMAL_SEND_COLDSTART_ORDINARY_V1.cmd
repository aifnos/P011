@echo off
setlocal
cd /d "%~dp0"
python -I -B host\device_formal_send_coldstart_ordinary_v1_check.py --stage-device
set "MTA_CHECK_EXIT=%ERRORLEVEL%"
echo Files-only ordinary v7 stage. No Parent, Owner, UI or RF.
exit /b %MTA_CHECK_EXIT%

