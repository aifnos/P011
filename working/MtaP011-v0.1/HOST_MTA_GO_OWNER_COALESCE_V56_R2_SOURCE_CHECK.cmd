@echo off
setlocal
cd /d "%~dp0"
python -I -B host\go_owner_coalesce_v56_r2_p011.py
exit /b %errorlevel%
