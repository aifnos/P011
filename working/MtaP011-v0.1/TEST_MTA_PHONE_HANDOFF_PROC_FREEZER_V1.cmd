@echo off
setlocal
cd /d "%~dp0"
rem Explicit original receive window. Root: fresh baseline, phone readiness, native READY.
rem No accept/send/file/UI/record cleanup. This is not full phone compatibility acceptance.
py -3.12 -I -B "host\device_phone_handoff_proc_freezer_v1_check.py" --check-device %*
exit /b %errorlevel%
