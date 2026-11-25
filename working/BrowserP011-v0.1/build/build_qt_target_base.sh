#!/bin/sh
set -eu
TASK_WORK=/browser-work
BUILD="$TASK_WORK/build-target-qtbase-v4-threads"
mkdir -p "$BUILD" "$TASK_WORK/target-qt"
cd "$BUILD"
if [ ! -f build.ninja ]; then
    cmake -G Ninja -S "$TASK_WORK/sources/qtbase-6.8.5" -B . \
        -DCMAKE_TOOLCHAIN_FILE=/build-defs/armv7-qt6.cmake \
        -DQT_HOST_PATH="$TASK_WORK/host-qt" \
        -DCMAKE_PREFIX_PATH="$TASK_WORK/prefix" \
        -DCMAKE_INSTALL_PREFIX=/opt/p011-browser-6.8.5 \
        -DCMAKE_STAGING_PREFIX="$TASK_WORK/target-qt" \
        -DCMAKE_BUILD_TYPE=Release -DQT_BUILD_TESTS=OFF -DQT_BUILD_EXAMPLES=OFF \
        -DINPUT_opengl=es2 -DFEATURE_opengl=ON -DFEATURE_egl=ON \
        -DFEATURE_xcb=OFF -DFEATURE_vulkan=OFF -DFEATURE_eglfs=OFF \
        -DFEATURE_linuxfb=OFF -DFEATURE_glib=OFF -DFEATURE_icu=OFF \
        -DFEATURE_dbus=OFF -DFEATURE_fontconfig=ON -DFEATURE_sql=OFF \
        -DEGL_LIBRARY="$TASK_WORK/prefix/lib/libmali.so.0.28.0" \
        -DGLESv2_LIBRARY="$TASK_WORK/prefix/lib/libmali.so.0.28.0" \
        -DEGL_INCLUDE_DIR="$TASK_WORK/prefix/include" \
        -DGLESv2_INCLUDE_DIR="$TASK_WORK/prefix/include" \
        -DCMAKE_BUILD_RPATH_USE_ORIGIN=ON
fi
# Qt TLS/platform plugins are MODULE targets, whose linker flags have a separate
# cache entry from SHARED libraries. Keep their C++ runtime on the same old ABI.
cmake -S "$TASK_WORK/sources/qtbase-6.8.5" -B . \
    -DCMAKE_MODULE_LINKER_FLAGS="-L$TASK_WORK/cxx-runtime-threaded/lib -L$TASK_WORK/prefix/lib -L/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/lib -L/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/usr/lib -Wl,-rpath-link,$TASK_WORK/cxx-runtime-threaded/lib:$TASK_WORK/prefix/lib:/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/lib:/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/usr/lib"
cmake --build . --target Core --parallel "${P011_BUILD_JOBS:-4}"
printf 'TARGET_QT_CORE_BUILT=%s/lib\n' "$BUILD"
cmake --build . --parallel "${P011_BUILD_JOBS:-4}"
cmake --install .
printf 'TARGET_QT_BASE_READY=%s\n' "$TASK_WORK/target-qt"
