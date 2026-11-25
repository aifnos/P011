#!/bin/sh
set -eu
TASK_WORK=/browser-work
BUILD="$TASK_WORK/build-host-gn"
mkdir -p "$BUILD" "$TASK_WORK/host-tools/bin"
python3 "$TASK_WORK/sources/qtwebengine-6.8.5/src/3rdparty/gn/build/gen.py" \
    --no-last-commit-position --no-static-libstdc++ --out-path "$BUILD" \
    --cc /usr/bin/gcc --cxx /usr/bin/g++ --ld /usr/bin/g++ \
    --allow-warnings --platform linux --ar /usr/bin/ar \
    --qt-version '6.8.5.qtwebengine.qt.io'
ninja -C "$BUILD" -j4 -l4 gn
cp "$BUILD/gn" "$TASK_WORK/host-tools/bin/gn"
"$TASK_WORK/host-tools/bin/gn" --version
