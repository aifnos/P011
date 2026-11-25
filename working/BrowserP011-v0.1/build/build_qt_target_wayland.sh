#!/bin/sh
set -eu
TASK_WORK=/browser-work
BUILD="$TASK_WORK/build-target-qtwayland"
mkdir -p "$BUILD"
cd "$BUILD"
export PATH="$TASK_WORK/host-tools/bin:$PATH"
if [ ! -f build.ninja ]; then
    "$TASK_WORK/target-qt/bin/qt-configure-module" "$TASK_WORK/sources/qtwayland-6.8.5" -- \
        -DCMAKE_TOOLCHAIN_FILE=/build-defs/armv7-qt6.cmake \
        -DQT_HOST_PATH="$TASK_WORK/host-qt" \
        -DCMAKE_PREFIX_PATH="$TASK_WORK/target-qt;$TASK_WORK/prefix" \
        -DCMAKE_INSTALL_PREFIX=/opt/p011-browser-6.8.5 \
        -DCMAKE_STAGING_PREFIX="$TASK_WORK/target-qt" \
        -DCMAKE_BUILD_TYPE=Release -DQT_BUILD_TESTS=OFF -DQT_BUILD_EXAMPLES=OFF \
        -DFEATURE_wayland_client=ON -DFEATURE_wayland_server=OFF \
        -DFEATURE_wayland_client_wl_shell=ON \
        -DFEATURE_wayland_egl=ON \
        -DEGL_LIBRARY="$TASK_WORK/prefix/lib/libmali.so.0.28.0" \
        -DGLESv2_LIBRARY="$TASK_WORK/prefix/lib/libmali.so.0.28.0" \
        -DEGL_INCLUDE_DIR="$TASK_WORK/prefix/include" \
        -DGLESv2_INCLUDE_DIR="$TASK_WORK/prefix/include"
fi
cmake -S "$TASK_WORK/sources/qtwayland-6.8.5" -B . \
    -DCMAKE_INSTALL_PREFIX=/opt/p011-browser-6.8.5 \
    -DCMAKE_STAGING_PREFIX="$TASK_WORK/target-qt"
cmake --build . --parallel "${P011_BUILD_JOBS:-4}"
cmake --install .
printf 'TARGET_QT_WAYLAND_READY=%s\n' "$TASK_WORK/target-qt"
