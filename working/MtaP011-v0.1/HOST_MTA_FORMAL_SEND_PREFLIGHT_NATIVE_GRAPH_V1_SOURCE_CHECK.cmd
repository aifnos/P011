@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\formal_send_preflight_native_graph_v1_source_check.py"
set "MTA_EXIT=%ERRORLEVEL%"
echo SOURCE_EXIT=%MTA_EXIT%
exit /b %MTA_EXIT%
