@echo off
setlocal
cd /d "%~dp0"
echo PC-only one fixed automatic receive HOST-model method.
echo No ADB, RF, P011 deployment or phone interop test.
py -3 -B host\client_status_v35_r2_check.py
if errorlevel 1 goto failed
echo Selected HOST model passed. This is not P011 transfer acceptance.
echo Result ZIP path is printed above. Existing evidence is preserved.
pause
exit /b 0
:failed
echo Check failed. Preserve the ZIP and private raw logs. No repair is attempted.
pause
exit /b 1
