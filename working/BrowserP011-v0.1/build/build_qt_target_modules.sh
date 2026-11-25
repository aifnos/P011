#!/bin/sh
set -eu
TASK_WORK=/browser-work
for module in qtshadertools qtdeclarative qtwebchannel; do
    BUILD="$TASK_WORK/build-target-$module"
    STYLE_ARGS=
    if [ "$module" = qtdeclarative ]; then
        # Embedded runtime uses Basic; avoid building five unrelated style trees.
        STYLE_ARGS='-DFEATURE_quickcontrols2_basic=ON -DFEATURE_quickcontrols2_fusion=OFF -DFEATURE_quickcontrols2_fluentwinui3=OFF -DFEATURE_quickcontrols2_imagine=OFF -DFEATURE_quickcontrols2_material=OFF -DFEATURE_quickcontrols2_universal=OFF'
    fi
    mkdir -p "$BUILD"
    cd "$BUILD"
    if [ ! -f build.ninja ]; then
        "$TASK_WORK/target-qt/bin/qt-configure-module" "$TASK_WORK/sources/$module-6.8.5" -- \
            -DCMAKE_TOOLCHAIN_FILE=/build-defs/armv7-qt6.cmake \
            -DQT_HOST_PATH="$TASK_WORK/host-qt" \
            -DCMAKE_PREFIX_PATH="$TASK_WORK/target-qt;$TASK_WORK/prefix" \
            -DCMAKE_INSTALL_PREFIX=/opt/p011-browser-6.8.5 \
            -DCMAKE_STAGING_PREFIX="$TASK_WORK/target-qt" \
            -DCMAKE_BUILD_TYPE=Release -DQT_BUILD_TESTS=OFF -DQT_BUILD_EXAMPLES=OFF \
            -DEGL_LIBRARY="$TASK_WORK/prefix/lib/libmali.so.0.28.0" \
            -DGLESv2_LIBRARY="$TASK_WORK/prefix/lib/libmali.so.0.28.0" \
            -DEGL_INCLUDE_DIR="$TASK_WORK/prefix/include" \
            -DGLESv2_INCLUDE_DIR="$TASK_WORK/prefix/include" $STYLE_ARGS
    fi
    cmake -S "$TASK_WORK/sources/$module-6.8.5" -B . \
        -DCMAKE_INSTALL_PREFIX=/opt/p011-browser-6.8.5 \
        -DCMAKE_STAGING_PREFIX="$TASK_WORK/target-qt" $STYLE_ARGS
    cmake --build . --parallel "${P011_BUILD_JOBS:-4}"
    cmake --install .
    printf 'TARGET_QT_MODULE_READY=%s\n' "$module"
done
