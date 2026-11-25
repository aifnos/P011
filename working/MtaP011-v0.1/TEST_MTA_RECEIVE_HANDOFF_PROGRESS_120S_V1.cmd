@echo off
setlocal
rem Explicit peer-progress15s within actual-ready120s; frozen compat-v2 graph.
rem Original worker may start real Parent/F Wi-Fi. No accept/send/file/UI/Disconnect.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_handoff_progress_120s_v1_check.py" --check-device %*
exit /b %errorlevel%
