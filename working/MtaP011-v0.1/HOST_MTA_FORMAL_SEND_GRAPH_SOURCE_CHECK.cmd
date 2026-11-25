@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\formal_send_graph_source_check.py"
set "MTA_SEND_GRAPH_SOURCE_EXIT=%ERRORLEVEL%"
echo HOST_MTA_FORMAL_SEND_GRAPH_SOURCE_EXIT=%MTA_SEND_GRAPH_SOURCE_EXIT%
exit /b %MTA_SEND_GRAPH_SOURCE_EXIT%
