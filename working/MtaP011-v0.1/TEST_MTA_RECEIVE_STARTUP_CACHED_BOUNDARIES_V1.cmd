@echo off
py -3.12 -E -s -B "%~dp0host\device_receive_startup_cached_boundaries_v1_check.py" --check-device
