@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\receive_filecenter_product_check.py"
set "MTA_FILECENTER_EXIT=%ERRORLEVEL%"
echo HOST_MTA_RECEIVE_FILECENTER_PRODUCT_EXIT=%MTA_FILECENTER_EXIT%
exit /b %MTA_FILECENTER_EXIT%
