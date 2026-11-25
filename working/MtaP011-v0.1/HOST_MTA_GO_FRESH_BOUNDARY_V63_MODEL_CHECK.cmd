@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 exit /b 1
echo PC MODEL only: one fixed GO62 fresh-boundary HOST63 affected method.
echo ROOT must review frozen source before the unique first execution.
echo No ADB, physical device, RF, service, phone or old test is started.
echo New full GO algorithms use explicit Linux/FD/Proc/netlink/Unix/clock models.
echo Original grant/canonical/close gates and periods remain; unknown stays pending.
py -3 -B "host\go_fresh_boundary_v63_check.py"
set "P011_GO_FRESH_BOUNDARY_EXIT=%errorlevel%"
if not "%P011_GO_FRESH_BOUNDARY_EXIT%"=="0" goto failed
echo Fixed HOST model method passed, not physical P011 or whole Native restoration.
echo New ZIP path is printed above. Existing evidence is preserved.
pause
exit /b %P011_GO_FRESH_BOUNDARY_EXIT%
:failed
echo Check failed. Preserve ZIP, private raw and fixed input snapshot.
echo No automatic retry, quota expansion, renewal, deletion or repair is attempted.
pause
exit /b %P011_GO_FRESH_BOUNDARY_EXIT%

