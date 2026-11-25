@echo off
setlocal
cd /d "%~dp0"
echo PC-only new peer checks. No ADB, radio or deployment.
py -3 -B host\client_peer_v29_check.py codec
if errorlevel 1 goto failed
py -3 -B host\client_peer_v29_check.py native
if errorlevel 1 goto failed
echo HOST model checks passed. P011 and phone interoperability are NOT verified.
pause
exit /b 0
:failed
echo Check failed. Original raw streams are retained in results.
pause
exit /b 1
