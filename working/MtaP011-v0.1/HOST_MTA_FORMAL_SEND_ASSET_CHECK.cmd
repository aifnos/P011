@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\formal_send_asset_source_check.py"
set "MTA_SEND_ASSET_EXIT=%ERRORLEVEL%"
echo SOURCE_MTA_FORMAL_SEND_ASSET_EXIT=%MTA_SEND_ASSET_EXIT%
exit /b %MTA_SEND_ASSET_EXIT%
