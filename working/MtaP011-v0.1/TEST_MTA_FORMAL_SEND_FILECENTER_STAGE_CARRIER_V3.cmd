@echo off
cd /d "%~dp0"
if "%~1"=="" goto local
if not "%~1"=="--stage" exit /b 2
if not "%~3"=="" exit /b 2
if "%~2"=="sender" goto stage
if "%~2"=="observer" goto stage
if "%~2"=="ordinary" goto stage
exit /b 2
:local
py -3.12 -I -B host\device_formal_send_filecenter_stage_carrier_v3_check.py
exit /b %errorlevel%
:stage
py -3.12 -I -B host\device_formal_send_filecenter_stage_carrier_v3_check.py --stage "%~2"
exit /b %errorlevel%
