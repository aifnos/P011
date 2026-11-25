@echo off
setlocal
cd /d "%~dp0"
echo PC-only one native refusal and local cleanup HOST-model method.
echo No ADB, RF, full F restore, P011 deployment or phone test.
py -3 -B host\client_budget_refusal_v36_r2_check.py
if errorlevel 1 goto failed
echo Selected HOST boundary passed. This is not device restoration acceptance.
echo Result ZIP path is printed above. Existing evidence is preserved.
pause
exit /b 0
:failed
echo Check failed. Preserve the ZIP and private raw logs. No repair is attempted.
pause
exit /b 1
