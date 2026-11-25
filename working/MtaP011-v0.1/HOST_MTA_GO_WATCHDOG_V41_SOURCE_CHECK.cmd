@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 exit /b 1
echo PC SOURCE verification only. This does not run ADB or repeat the device trial.
echo Retained device result: CURRENT_GO_WATCHDOG_V41_RESULTS_README.md
powershell -NoProfile -Command "if ((Get-FileHash -LiteralPath 'host\go_watchdog_device_v41_p011.py' -Algorithm SHA256).Hash -ne '5ce917604e3838c955dec5208e3d3bbf5031336a93426c016d5542dbdf79d099') { exit 2 }"
if errorlevel 1 goto binding_failed
python -B "host\go_watchdog_device_v41_p011.py"
set "P011_GO_SOURCE_EXIT=%errorlevel%"
echo This result is PC source identity validation, not a new hardware or phone acceptance.
pause
exit /b %P011_GO_SOURCE_EXIT%
:binding_failed
echo Driver identity could not be verified. No Python or device trial was started.
pause
exit /b 2
