@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 exit /b 1
echo PC-only: one fixed automatic receive HOST-model method.
echo The original result already passed. Run manually only for a needed new verification.
echo See CURRENT_CLIENT_V38_V39_HOST_RESULTS_README.md for retained evidence.
echo No ADB, RF, P011 deployment, device restoration or phone acceptance.
py -3 -B "host\client_refusal_prescreen_v38_r2_check.py"
set "P011_HOST_CHECK_EXIT=%errorlevel%"
if not "%P011_HOST_CHECK_EXIT%"=="0" goto failed
echo Selected HOST model passed. This is not physical P011 transfer acceptance.
echo New result ZIP path is printed above. Existing evidence is preserved.
pause
exit /b %P011_HOST_CHECK_EXIT%
:failed
echo Check failed. Preserve the ZIP and private raw logs. No retry or repair is attempted.
pause
exit /b %P011_HOST_CHECK_EXIT%
