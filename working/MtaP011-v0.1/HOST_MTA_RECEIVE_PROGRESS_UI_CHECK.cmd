@echo off
setlocal
cd /d "%~dp0"
echo PC-only receive-progress Qt UI check. No ADB, service, RF or phone.
echo One new method, eight status fixtures, one isolated 30-second child. No retry.
echo Brief HOST Windows Qt windows use software rendering and HOST labels.
echo Two unedited 800x268 captures show archive download and unpack/check progress.
set "P011_RECEIVE_UI_PYTHON=C:\Users\P011_USER\AppData\Local\Programs\Python\Python312\python.exe"
if not exist "%P011_RECEIVE_UI_PYTHON%" (
  echo Fixed Python3.12 executable is missing. Nothing was tested.
  pause
  exit /b 2
)
"%P011_RECEIVE_UI_PYTHON%" -I -B "%~dp0host\receive_progress_ui_check.py"
set "P011_RECEIVE_UI_EXIT=%ERRORLEVEL%"
echo Exit: %P011_RECEIVE_UI_EXIT%
echo HOST UI with status fixtures only. No receive, CRC, commit, ACK or restore claim.
pause
exit /b %P011_RECEIVE_UI_EXIT%
