@echo off
setlocal
cd /d "%~dp0"
echo PC-only typed IPC checks. No ADB, RF, Loader, child launch or phone test.
for %%S in (codec decision rejection progress) do (
  py -3 -B host\client_receive_ipc_v31_check.py %%S
  if errorlevel 1 goto failed
)
echo Four selected typed IPC checks passed. Result ZIP locations are printed above.
pause
exit /b 0
:failed
echo Check failed. Preserve result ZIP and private raw logs; no device repair is attempted.
pause
exit /b 1
