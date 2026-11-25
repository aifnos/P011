@echo off
setlocal
cd /d "%~dp0"
echo PC-only HOST Qt UI80 check. No ADB, service, RF or phone operation.
echo One new UI method, eight inert-HTTP fixtures, one 30-second child. No retry.
echo Public success ZIP includes an actual unedited HOST 800x268 screenshot.
set "P011_UI80_PYTHON=C:\Users\P011_USER\AppData\Local\Programs\Python\Python312\python.exe"
if not exist "%P011_UI80_PYTHON%" (
  echo Fixed Python3.12 executable is missing. Nothing was tested.
  pause
  exit /b 2
)
"%P011_UI80_PYTHON%" -I -B "%~dp0host\go_send_ui_v80_check.py"
set "P011_UI80_EXIT=%ERRORLEVEL%"
echo Exit: %P011_UI80_EXIT%
echo HOST Qt / HTTP-model evidence only. No P011 send or restoration claim.
pause
exit /b %P011_UI80_EXIT%
