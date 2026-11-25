@echo off
setlocal
cd /d "%~dp0"
echo PC-only Qt file navigation test. No ADB, network or media playback.
echo Results and a sanitized ZIP are written under results.
py -3 -B "%~dp0host\file_navigation_v68_r2_check.py"
set "P011_NAV_EXIT=%ERRORLEVEL%"
echo Exit: %P011_NAV_EXIT%
pause
exit /b %P011_NAV_EXIT%
