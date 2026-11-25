#!/bin/sh
set -eu
TASK_WORK=/browser-work
BUILD="$TASK_WORK/build-browser-app"
mkdir -p "$BUILD" /browser-output/bin
cmake -G Ninja -S /app-source -B "$BUILD" \
    -DCMAKE_TOOLCHAIN_FILE=/build-defs/armv7-qt6.cmake \
    -DQT_HOST_PATH="$TASK_WORK/host-qt" \
    -DCMAKE_PREFIX_PATH="$TASK_WORK/target-qt;$TASK_WORK/prefix" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_BUILD_RPATH_USE_ORIGIN=ON \
    -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
    -DEGL_LIBRARY="$TASK_WORK/prefix/lib/libmali.so.0.28.0" \
    -DGLESv2_LIBRARY="$TASK_WORK/prefix/lib/libmali.so.0.28.0" \
    -DEGL_INCLUDE_DIR="$TASK_WORK/prefix/include" \
    -DGLESv2_INCLUDE_DIR="$TASK_WORK/prefix/include"
cmake --build "$BUILD" --parallel 4
cp "$BUILD/p011-browser-probe" /browser-output/bin/p011-browser-probe
python3 /build-defs/package_browser.py
