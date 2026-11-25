@echo off
setlocal
cd /d "%~dp0"
rem Default PC SOURCE. Existing phone observer on the actual classification graph.
rem No tests, pre-staging or device actions unless --check-device is explicit.
py -3.12 -I -B "host\device_receive_handoff_classification_v1_check.py" %*
exit /b %errorlevel%
