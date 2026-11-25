@echo off
cd /d "%~dp0"
python -B host\device_wpa_config_norf.py --execute-reviewed
set "MTA_CONFIG_CHECK_EXIT=%errorlevel%"
pause
exit /b %MTA_CONFIG_CHECK_EXIT%
