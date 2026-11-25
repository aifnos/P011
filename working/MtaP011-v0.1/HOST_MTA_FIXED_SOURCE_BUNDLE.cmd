@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B "host\build_fixed_source_bundle.py"
exit /b %ERRORLEVEL%
