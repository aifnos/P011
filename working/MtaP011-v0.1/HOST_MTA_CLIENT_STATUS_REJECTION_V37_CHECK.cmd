@echo off
setlocal
cd /d "%~dp0"
echo PC-only: one native STATUS pre-dispatch rejection method.
echo No ADB, valid live ticket, full receive, RF or device recovery test.
py -3 -B host\client_status_rejection_v37_check.py
if errorlevel 1 goto failed
echo Selected HOST rejection boundary passed; this is not device acceptance.
echo Result ZIP path is printed above. Existing evidence is preserved.
pause
exit /b 0
:failed
echo Check failed. Preserve the ZIP and private raw logs. No retry or repair.
pause
exit /b 1
