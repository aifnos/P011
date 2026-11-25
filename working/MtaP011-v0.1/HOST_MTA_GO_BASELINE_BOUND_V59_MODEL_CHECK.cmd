@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 exit /b 1
echo PC MODEL only: one fixed GO58 bounded-stage HOST method, nine modeled cases.
echo The original HOST59 result already passed. Do not rerun merely to obtain logs.
echo See CURRENT_GO_BASELINE_BUDGET_V58_FINDING.md for retained evidence and scope.
echo No ADB, device, service, RF, baseline run, reserve, fork, restore or phone test.
echo Model until301 is not the P011 active45 period or a performance acceptance.
py -3 -B "host\go_baseline_bound_v59_check.py"
set "P011_GO_BASELINE_BOUND_EXIT=%errorlevel%"
if not "%P011_GO_BASELINE_BOUND_EXIT%"=="0" goto failed
echo Fixed HOST boundary passed. This is not physical P011 or full restoration.
echo New result ZIP path is printed above. Existing evidence is preserved.
pause
exit /b %P011_GO_BASELINE_BOUND_EXIT%
:failed
echo Check failed. Preserve the ZIP, private raw streams and fixed input snapshot.
echo No retry, deadline renewal, cleanup of old data or automatic repair is attempted.
pause
exit /b %P011_GO_BASELINE_BOUND_EXIT%
