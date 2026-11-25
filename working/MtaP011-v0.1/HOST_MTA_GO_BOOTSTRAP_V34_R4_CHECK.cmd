@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 exit /b 1
echo PC-only: one fixed GO17 HOST algorithm method with eleven modeled flows.
echo The original r4 result already passed. Do not rerun merely to obtain logs.
echo See CURRENT_GO_V34_HOST_RESULTS_README.md for retained PASS and FAIL evidence.
echo No ADB, device, RF, phone, real child exec, service start or automatic repair.
py -3 -B "host\go_bootstrap_native_v34_r4_check.py"
set "P011_GO_HOST_EXIT=%errorlevel%"
if not "%P011_GO_HOST_EXIT%"=="0" goto failed
echo Fixed GO17 HOST model passed. This is not physical Linux or P011 acceptance.
echo New result ZIP path is printed above. Existing evidence is preserved.
pause
exit /b %P011_GO_HOST_EXIT%
:failed
echo Check failed. Preserve the ZIP, private raw logs and fixed input snapshot.
echo No retry, quota expansion, cleanup of partial data or repair is attempted.
pause
exit /b %P011_GO_HOST_EXIT%
