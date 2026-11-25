@echo off
cd /d "%~dp0"
py -B host\client_init_tmp_alias_v11_p011.py
exit /b %errorlevel%
