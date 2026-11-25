@echo off
setlocal
cd /d "%~dp0"
rem ROOT only, one new actual guard/alias/boundary HOST component contract; no graph/RF.
py -3.12 -I -B "tests\test_receive_alias_clock_v1.py"
exit /b %errorlevel%
