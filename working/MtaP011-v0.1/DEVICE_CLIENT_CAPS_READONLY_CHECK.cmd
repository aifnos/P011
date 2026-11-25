@echo off
cd /d "%~dp0"
echo P011 pinned read-only CLIENT capability check.
echo No RF, network changes, staging, locks or pending cleanup.
echo A failed PHY precondition is not proof of hardware damage.
echo This does not test file transfer or restore the original network.
python -B host\device_client_caps_readonly.py --source-check-only
if errorlevel 1 goto end
python -B host\device_client_caps_readonly.py --execute-reviewed --expected-checker-sha256 948a6c8dfdbb134fcd2f060ff30447c96e4111e1af135f89174ec1f3e3c00a21
:end
pause
