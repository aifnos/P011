@echo off
setlocal
pushd "%~dp0"
py -3.12 -I -B host\client_service_owner_v70_check.py
set "P011_SERVICE_OWNER_EXIT=%ERRORLEVEL%"
popd
exit /b %P011_SERVICE_OWNER_EXIT%
