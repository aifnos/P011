@echo off
setlocal
pushd "%~dp0"
py -3.12 -I -B "host\go_send_key_close_v79_check.py"
set "P011_CHECK_EXIT=%ERRORLEVEL%"
popd
exit /b %P011_CHECK_EXIT%
