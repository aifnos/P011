@echo off
setlocal
cd /d "%~dp0"
rem One HOST-only receipt-read fault method. No graph, archived main, ADB or radio.
py -3.12 -I -B "host\phone_handoff_durable_window_receipt_fault_v1_check.py" %*
exit /b %errorlevel%
