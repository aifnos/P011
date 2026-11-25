@echo off
setlocal
rem Explicit actual-ready120s headless discovery with frozen compat-v2 graph.
rem No accept/send/UI. Original cancel/cleanup/pending remain strict.
cd /d "%~dp0"
py -3.12 -I -B "host\device_receive_phone_discovery_120s_v1_check.py" --check-device %*
exit /b %errorlevel%
