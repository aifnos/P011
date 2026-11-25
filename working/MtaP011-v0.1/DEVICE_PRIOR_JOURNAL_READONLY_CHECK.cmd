@echo off
cd /d "%~dp0"
python -B host\device_prior_journal_readonly.py --check-readonly
pause
