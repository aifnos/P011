@echo off
cd /d "%~dp0"
python -B host\device_candidate_permissions_readonly.py --check-readonly
pause
