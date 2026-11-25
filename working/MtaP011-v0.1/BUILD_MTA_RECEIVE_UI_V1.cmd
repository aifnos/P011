@echo off
setlocal
pushd "%~dp0"
py -3.12 -I -B host\build_formal_receive_ui_v1.py
set "P011_RECEIVE_UI_BUILD_EXIT=%ERRORLEVEL%"
popd
exit /b %P011_RECEIVE_UI_BUILD_EXIT%
