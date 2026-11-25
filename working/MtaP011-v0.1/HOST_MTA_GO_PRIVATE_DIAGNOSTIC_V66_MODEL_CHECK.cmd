@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 exit /b 1
echo PC PURE COMPONENT only: one new HOST66 timing32/stat6diff/FD2 bounds method.
echo ROOT must review final source pins before the unique first execution.
echo No ADB, device, service, RF, Loader load, Bootstrap run, fork or restoration.
echo Exact-class synthetic diagnostic data are not original producer permission.
py -3 -B "host\go_private_diagnostic_v66_check.py"
set "P011_GO_PRIVATE_DIAGNOSTIC_EXIT=%errorlevel%"
if not "%P011_GO_PRIVATE_DIAGNOSTIC_EXIT%"=="0" goto failed
echo Fixed pure component passed. Physical P011 and business restoration remain untested.
echo The new result ZIP path is printed above. Old source and evidence are preserved.
pause
exit /b %P011_GO_PRIVATE_DIAGNOSTIC_EXIT%
:failed
echo Check failed. Preserve private raw streams and fixed input snapshot.
echo No retry, renewed cap, cleanup of old results or automatic recovery is attempted.
pause
exit /b %P011_GO_PRIVATE_DIAGNOSTIC_EXIT%
