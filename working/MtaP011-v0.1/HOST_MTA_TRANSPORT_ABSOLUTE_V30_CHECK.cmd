@echo off
cd /d "%~dp0"
echo PC-only v30 new component checks. No ADB or P011 radio operation.
py -3 -B host\transport_absolute_v30_check.py bounds
if errorlevel 1 goto end
py -3 -B host\transport_absolute_v30_check.py tls
:end
pause
