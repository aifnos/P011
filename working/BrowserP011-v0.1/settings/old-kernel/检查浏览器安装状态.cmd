@echo off
setlocal
cd /d "%~dp0"
set "P011_TRANSPORT=%~1"
if "%P011_TRANSPORT%"=="" set "P011_TRANSPORT=1"
python -B host_legacy.py --action inspect --transport %P011_TRANSPORT%
exit /b %errorlevel%
