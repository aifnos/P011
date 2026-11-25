@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\formal_send_cleanup_budget_host_check.py"
set "MTA_SEND_CLEANUP_BUDGET_EXIT=%ERRORLEVEL%"
echo HOST_MTA_FORMAL_SEND_CLEANUP_BUDGET_EXIT=%MTA_SEND_CLEANUP_BUDGET_EXIT%
exit /b %MTA_SEND_CLEANUP_BUDGET_EXIT%
