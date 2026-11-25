@echo off
py -3.12 -E -s -B "%~dp0host\device_receive_publication_progress_v1_startup_check.py" --check-device
