@echo off
setlocal
cd /d "%~dp0"
echo PC-only HOST Qt UI80-R3 check. No ADB, service, RF or phone operation.
echo Only two remaining fixtures7-8, one 30-second child. No retry.
echo A brief HOST Windows Qt window may appear; software rendering only.
echo R1/R2 wholeFAIL stay preserved. Fixtures1-6 are not replayed.
echo This does not combine the eight fixtures into an overall PASS.
set "P011_UI80_R3_PYTHON=C:\Users\P011_USER\AppData\Local\Programs\Python\Python312\python.exe"
if not exist "%P011_UI80_R3_PYTHON%" (
  echo Fixed Python3.12 executable is missing. Nothing was tested.
  pause
  exit /b 2
)
"%P011_UI80_R3_PYTHON%" -I -B "%~dp0host\go_send_ui_v80_r3_check.py"
set "P011_UI80_R3_EXIT=%ERRORLEVEL%"
echo Exit: %P011_UI80_R3_EXIT%
echo HOST Qt / HTTP-model evidence only. No P011 send or restoration claim.
pause
exit /b %P011_UI80_R3_EXIT%
