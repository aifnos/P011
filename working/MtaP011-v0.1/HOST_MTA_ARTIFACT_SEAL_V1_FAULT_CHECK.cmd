@echo off
setlocal
cd /d "%~dp0"
py -3.12 -I -B host\host_artifact_seal_v1_fault_check.py
exit /b %errorlevel%
