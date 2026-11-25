@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 exit /b 1
echo PC MODEL only: one fixed GO60 Proc diagnostic HOST component method.
echo ROOT must review the frozen source before the unique first execution.
echo No ADB, device, service, RF, baseline, reserve, actors, pins, fork or restore.
echo Actual Reader unknown and Native refusal remain; no grant or ready is added.
echo Private diagnostic values stay in modeled assertions, not public raw output.
py -3 -B "host\go_proc_diagnostic_v61_check.py"
set "P011_GO_PROC_DIAGNOSTIC_EXIT=%errorlevel%"
if not "%P011_GO_PROC_DIAGNOSTIC_EXIT%"=="0" goto failed
echo Fixed HOST component passed. This is not physical P011 or full restoration.
echo New result ZIP path is printed above. Existing evidence is preserved.
pause
exit /b %P011_GO_PROC_DIAGNOSTIC_EXIT%
:failed
echo Check failed. Preserve the ZIP, private raw streams and fixed input snapshot.
echo No retry, deadline renewal, old-data deletion or automatic repair is attempted.
pause
exit /b %P011_GO_PROC_DIAGNOSTIC_EXIT%

