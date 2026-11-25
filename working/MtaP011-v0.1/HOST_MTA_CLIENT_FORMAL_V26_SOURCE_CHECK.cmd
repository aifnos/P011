@echo off
cd /d "%~dp0"
python host\client_formal_v26_source_check.py
exit /b %errorlevel%
