@echo off
setlocal
cd /d "%~dp0"
echo PC-only formal MTA Qt composition. No ADB, service, RF or phone.
echo One new method, four composition domains, one isolated 30-second child.
echo Two unedited 800x268 HOST captures. Delayed HTTP actions are explicit models.
set "P011_FORMAL_UI_PYTHON=C:\Users\P011_USER\AppData\Local\Programs\Python\Python312\python.exe"
if not exist "%P011_FORMAL_UI_PYTHON%" (
  echo Fixed Python3.12 is missing. Nothing was tested.
  pause
  exit /b 2
)
"%P011_FORMAL_UI_PYTHON%" -I -B "%~dp0host\formal_ui_composition_v1_check.py"
set "P011_FORMAL_UI_EXIT=%ERRORLEVEL%"
echo Exit: %P011_FORMAL_UI_EXIT%
echo HOST Qt composition only. Receive, send, admission and restoration stay unverified.
pause
exit /b %P011_FORMAL_UI_EXIT%
