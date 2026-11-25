@echo off
cd /d "%~dp0"
echo HOST source-only check for the reviewed CLIENT file component.
echo This does not start WSL or Docker, use ADB, write Linux test files,
echo change radios or networks, clear pending, or prove phone transfer.
python -B host\client_files_linux_check.py --source-check-only
set "MTA_CLIENT_FILES_HOST_EXIT=%ERRORLEVEL%"
pause
exit /b %MTA_CLIENT_FILES_HOST_EXIT%
