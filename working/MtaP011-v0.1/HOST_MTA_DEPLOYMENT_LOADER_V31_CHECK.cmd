@echo off
setlocal
cd /d "%~dp0"
echo PC-only frozen Loader check. No ADB, RF, executable launch or phone test.
py -3 -B host\client_deployment_loader_v31_check.py
if errorlevel 1 goto failed
echo One selected Loader method passed. The result ZIP path is printed above.
pause
exit /b 0
:failed
echo Check failed. Preserve the ZIP and private raw logs. No device repair is attempted.
pause
exit /b 1
