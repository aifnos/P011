@echo off
cd /d "%~dp0"
echo P011 finite synthetic UDP loopback: lo only, 2 sockets, 4 datagrams.
echo No RF, network configuration, DHCP ports, UI or user files.
echo Does not prove P2P binding, DHCP or phone interoperability.
echo Source pin mismatch stops the check. No automatic retry or reboot.
python -B host\device_udp_loopback.py --execute-reviewed --expected-checker-sha256 3319052523fb791ca1eb4bedd7fe449d4f663ae400f339f33b5d33b203d0fd87
pause
