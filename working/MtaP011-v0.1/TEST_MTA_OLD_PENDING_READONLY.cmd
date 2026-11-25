@echo off
setlocal
cd /d "%~dp0"
echo Read-only diagnosis of the one retained GO64 test reservation.
echo No radio, network change, reboot, record removal or phone-transfer claim.
py -3 -B host\device_go_pending_readonly_20261004.py --read-current
exit /b %errorlevel%
