@echo off
cd /d "%~dp0"
echo PC-only v29-r3 affected native model. No ADB or P011 radio operation.
echo The unchanged codec method is not rerun by this entry.
py -3 -B host\client_peer_v29_r3_check.py native
pause
