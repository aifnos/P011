@echo off
setlocal
cd /d "%~dp0"
echo PC-only UTF-8 file test. No ADB, radio or firmware operations.
echo Results and a sanitized ZIP are written under results.
py -3 -B "%~dp0host\file_utf8_v67_check.py"
set "P011_UTF8_EXIT=%ERRORLEVEL%"
echo Exit: %P011_UTF8_EXIT%
pause
exit /b %P011_UTF8_EXIT%
