@echo off
cd /d "%~dp0"
echo P011 finite synthetic TLS loopback. No radio, UI or user files.
echo Verifies a private candidate; changes only its exact 8 file permissions.
echo Does not prove Wi-Fi or phone interoperability. No restart on failure.
python -B host\device_tls.py
pause
