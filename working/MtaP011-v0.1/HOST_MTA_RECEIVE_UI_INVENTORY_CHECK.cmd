@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\receive_ui_inventory_check.py"
set "MTA_INVENTORY_EXIT=%ERRORLEVEL%"
echo HOST_MTA_RECEIVE_UI_INVENTORY_EXIT=%MTA_INVENTORY_EXIT%
exit /b %MTA_INVENTORY_EXIT%
