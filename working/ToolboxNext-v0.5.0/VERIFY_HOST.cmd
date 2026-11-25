@echo off
cd /d "%~dp0"
python -B host\verify_host.py
set "P011_VERIFY_EXIT=%ERRORLEVEL%"
echo.
echo PC-only verification finished. See the RESULT_DIR / RESULT_ZIP above.
pause
exit /b %P011_VERIFY_EXIT%
