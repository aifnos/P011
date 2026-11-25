@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 exit /b 1
echo PC MODEL only: two affected HOST63-r2 refusal domains, one new method.
echo ROOT must review frozen source before the unique first execution.
echo Original63 whole FAIL stays; ten completed domains are NOT rerun.
echo No ADB, device, physical RF, service, phone or old test starts.
echo Actual GO62 algorithms use explicit Linux/FD/Proc/netlink/Unix/clock models.
echo Original error, once-close and pending remain; diagnostics are best effort.
py -3 -B "host\go_fresh_boundary_v63_r2_check.py"
set "P011_GO_FRESH_BOUNDARY_R2_EXIT=%errorlevel%"
if not "%P011_GO_FRESH_BOUNDARY_R2_EXIT%"=="0" goto failed
echo New two-domain HOST model check passed, not whole63 or physical restoration.
echo New ZIP path is printed above. Existing evidence is preserved.
pause
exit /b %P011_GO_FRESH_BOUNDARY_R2_EXIT%
:failed
echo Preserve ZIP, private raw and fixed input snapshot.
echo No retry, quota expansion, renewal, deletion or repair is attempted.
pause
exit /b %P011_GO_FRESH_BOUNDARY_R2_EXIT%

