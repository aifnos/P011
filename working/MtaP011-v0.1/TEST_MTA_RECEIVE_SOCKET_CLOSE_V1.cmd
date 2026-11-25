@echo off
setlocal
pushd "%~dp0"
py -3.12 -I -B host\receive_socket_close_v1_contract_check.py %*
set "P011_RECEIVE_SOCKET_EXIT=%ERRORLEVEL%"
popd
exit /b %P011_RECEIVE_SOCKET_EXIT%
