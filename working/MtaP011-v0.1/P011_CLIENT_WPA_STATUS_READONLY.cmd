@echo off
cd /d "%~dp0"
echo Read-only original WPA STATUS; no scanning, network switching or repair.
python -B host\client_wpa_status_readonly.py --execute-readonly --expected-checker-sha256 99362b8c2a5872737d692672774afe000e630155a556ddef950869fb25a3e50b
exit /b %errorlevel%
