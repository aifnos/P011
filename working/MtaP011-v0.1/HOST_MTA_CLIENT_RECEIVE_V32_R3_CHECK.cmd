@echo off
setlocal
cd /d "%~dp0"
echo PC-only single receive model check. No ADB, RF or phone interoperability test.
py -3 -B host\client_receive_executor_v32_r3_check.py
if errorlevel 1 goto failed
echo The selected PC model method passed. This does not enable P011 send or receive.
echo Result ZIP path is printed above. Previously saved evidence is not overwritten.
pause
exit /b 0
:failed
echo Check failed. Preserve the ZIP and private raw logs. No device repair is attempted.
pause
exit /b 1
