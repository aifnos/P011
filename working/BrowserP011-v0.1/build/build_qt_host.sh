#!/bin/sh
set -eu
TASK_WORK=${P011_BROWSER_WORK:-/browser-work}
JOBS=${P011_BUILD_JOBS:-4}
HOST_PREFIX="$TASK_WORK/host-qt"
mkdir -p "$TASK_WORK/sources" "$TASK_WORK/build-host-qtbase" "$HOST_PREFIX"

extract_module() {
    module=$1
    target="$TASK_WORK/sources/$module-6.8.5"
    archive="/input-downloads/$module-everywhere-opensource-src-6.8.5.tar.xz"
    mkdir -p "$target"
    if [ ! -f "$target/.browser685-extracted" ]; then
        test -s "$archive"
        sha256sum "$archive"
        tar -xJf "$archive" -C "$target" --strip-components=1
        touch "$target/.browser685-extracted"
    fi
}

extract_module qtbase
cd "$TASK_WORK/build-host-qtbase"
if [ ! -f "$HOST_PREFIX/lib/cmake/Qt6Core/Qt6CoreConfig.cmake" ]; then
if [ ! -f build.ninja ]; then
    "$TASK_WORK/sources/qtbase-6.8.5/configure" \
        -prefix "$HOST_PREFIX" -opensource -confirm-license -release \
        -nomake examples -nomake tests -no-opengl -no-xcb -no-icu \
        -no-dbus -no-glib -no-feature-vulkan -no-feature-eglfs \
        -no-feature-linuxfb
fi
cmake --build . --parallel "$JOBS"
cmake --install .
fi

for module in qtshadertools qtdeclarative qtwayland qtwebchannel; do
    extract_module "$module"
    mkdir -p "$TASK_WORK/build-host-$module"
    cd "$TASK_WORK/build-host-$module"
    if [ ! -f build.ninja ]; then
        "$HOST_PREFIX/bin/qt-configure-module" "$TASK_WORK/sources/$module-6.8.5" \
            -- -DQT_BUILD_EXAMPLES=OFF -DQT_BUILD_TESTS=OFF
    fi
    cmake --build . --parallel "$JOBS"
    cmake --install .
done
printf 'HOST_QT_READY=%s\n' "$HOST_PREFIX"
