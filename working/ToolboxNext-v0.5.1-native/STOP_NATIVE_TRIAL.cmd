@echo off
cd /d "%~dp0"
python -B host\native_trial.py stop
set "P011_NATIVE_EXIT=%ERRORLEVEL%"
echo.
echo Check the collected result. A stop request alone is not proof of completion.
pause
exit /b %P011_NATIVE_EXIT%
