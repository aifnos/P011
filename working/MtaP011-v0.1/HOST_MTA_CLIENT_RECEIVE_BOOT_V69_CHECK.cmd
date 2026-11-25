@echo off
setlocal
pushd "%~dp0"
py -3.12 -I -B host\client_receive_boot_v69_check.py
set "P011_RECEIVE_BOOT_EXIT=%ERRORLEVEL%"
popd
exit /b %P011_RECEIVE_BOOT_EXIT%
