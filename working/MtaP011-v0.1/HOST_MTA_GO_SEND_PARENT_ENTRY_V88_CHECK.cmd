@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\go_send_parent_entry_v88_check.py"
set "MTA_HOST88_EXIT=%ERRORLEVEL%"
echo HOST-only affected checks finished. No P011 or phone action.
pause
exit /b %MTA_HOST88_EXIT%
