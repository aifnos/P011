@echo off
setlocal
cd /d "%~dp0"
rem Explicit original120s discovery/peer15s observer on the actual graph.
rem Original runtime preflight/stage/load_owner is retained; no separate stage.
rem Requires fresh phone readiness/current baseline; click only after native READY.
rem Parent/F may initialize Wi-Fi. No accept/send/file/UI/Disconnect/record cleanup.
py -3.12 -I -B "host\device_receive_handoff_classification_v1_check.py" --check-device %*
exit /b %errorlevel%
