@echo off
setlocal
cd /d "%~dp0"
echo PC-only one typed IPC method. No ADB, RF, Parent spawn or phone test.
py -3 -B host\client_terminal_v34_check.py
if errorlevel 1 goto failed
echo The selected IPC method passed. This is not a complete P011 file transfer.
echo Result ZIP path is printed above. Existing evidence is preserved.
pause
exit /b 0
:failed
echo Check failed. Preserve the ZIP and private raw logs. No device repair is attempted.
pause
exit /b 1
