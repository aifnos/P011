#!/bin/sh
set -eu
python3 /build-defs/prepare_target_prefix.py
sh /build-defs/build_wayland_dependency.sh
