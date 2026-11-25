@echo off
setlocal
cd /d "%~dp0"
rem ROOT: isolated fixed graph75 preparation and original startup-close; no RF/UI/phone.
py -3.12 -I -B "host\device_receive_profile_classification_clock_v1_check.py" --check-device %*
exit /b %errorlevel%
