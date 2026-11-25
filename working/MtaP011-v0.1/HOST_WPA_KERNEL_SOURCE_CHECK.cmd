@echo off
setlocal
cd /d "%~dp0"
python -B host\wpa_kernel_profile_readonly.py
exit /b %ERRORLEVEL%
