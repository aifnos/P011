@echo off
setlocal
cd /d "%~dp0"
rem Explicit original120s window/peer15s; passive stage DATA only added.
rem Original worker may start real Parent/F Wi-Fi; no accept/send/file/UI/Disconnect.
py -3.12 -I -B "host\device_receive_handoff_progress_120s_v2_check.py" --check-device %*
exit /b %errorlevel%
