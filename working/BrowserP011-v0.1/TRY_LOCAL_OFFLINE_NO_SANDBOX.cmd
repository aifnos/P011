@echo off
setlocal
cd /d "%~dp0"
set "P011_BROWSER_TRANSPORT=1"
if not "%~1"=="" set "P011_BROWSER_TRANSPORT=%~1"
if not exist "out\qt685\bin\p011-browser-probe" (
  echo Qt 6.8.5 ARM browser payload is not built yet. See CURRENT_STATUS.md.
  exit /b 2
)
echo Explicit low-privilege OFFLINE local fixture experiment; Chromium sandbox disabled.
echo No external website or account is opened. This does not verify secure web browsing.
python -B host\trial.py --transport "%P011_BROWSER_TRANSPORT%" --payload out\qt685 --expected-snapshot state\selected-device.json --seconds 30 --uid 65534 --gid 44 --shell-integration wl-shell --offline-no-sandbox
exit /b %errorlevel%
