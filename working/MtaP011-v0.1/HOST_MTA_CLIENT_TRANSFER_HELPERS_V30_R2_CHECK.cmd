@echo off
setlocal
cd /d "%~dp0"
echo PC-only helper checks. No ADB, RF, child launch, phone or native CLIENT lifecycle.
py -3 -B host\client_transfer_boundaries_v30_r2_check.py dispose
if errorlevel 1 goto failed
py -3 -B host\client_transfer_boundaries_v30_r2_check.py passive
if errorlevel 1 goto failed
echo Both selected helper checks passed. Result ZIP locations are printed above.
pause
exit /b 0
:failed
echo Check failed. Keep the printed result ZIP and private raw logs; no device repair is attempted.
pause
exit /b 1
