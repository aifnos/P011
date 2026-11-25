@echo off
cd /d "%~dp0"
python -B host\native_trial.py smoke
set "P011_NATIVE_EXIT=%ERRORLEVEL%"
echo.
echo Automated native smoke complete. Inspect NATIVE_TRIAL_PASS and the result ZIP.
pause
exit /b %P011_NATIVE_EXIT%
