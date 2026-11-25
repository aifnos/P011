@echo off
setlocal
cd /d "%~dp0"
echo PC-only one original-parent-cap first issuance boundary method.
echo No ADB, RF, Parent spawn, full file receive or phone test.
py -3 -B host\client_parent_cap_v33_r2_check.py
if errorlevel 1 goto failed
echo The selected HOST boundary passed. This is not P011 transfer acceptance.
echo Result ZIP path is printed above. Existing evidence is preserved.
pause
exit /b 0
:failed
echo Check failed. Preserve the ZIP and private raw logs. No device repair is attempted.
pause
exit /b 1
