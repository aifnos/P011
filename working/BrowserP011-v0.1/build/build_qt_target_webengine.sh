#!/bin/sh
set -eu
TASK_WORK=/browser-work
BUILD=${P011_WEBENGINE_BUILD:-/browser-objects/qtwebengine-6.8.5}
JOBS=${P011_WEBENGINE_JOBS:-4}
case "$JOBS" in 4|8|12) ;; *) echo 'Only bounded jobs=4, jobs=8 or jobs=12 supported' >&2; exit 2;; esac
mkdir -p "$BUILD" "$TASK_WORK/toolchain"
# Skia uses Expat's stable public parser API; keep its public architecture-
# selected headers beside the already verified ARM Expat library in the prefix.
for header in expat.h expat_external.h; do
    if [ ! -f "$TASK_WORK/prefix/include/$header" ]; then
        cp "/usr/include/$header" "$TASK_WORK/prefix/include/$header"
    fi
done
cat > "$TASK_WORK/toolchain/browser685-webengine-cc" <<'SH'
#!/bin/sh
exec /usr/bin/arm-linux-gnueabihf-gcc-11 \
 --sysroot=/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot \
 -B/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/usr/lib/ \
 -B/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/lib/ \
 -nostdinc -isystem /usr/lib/gcc-cross/arm-linux-gnueabihf/11/include \
 -isystem /opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/usr/include \
 -L/browser-work/cxx-runtime-threaded/lib -L/browser-work/prefix/lib \
 -Wl,-rpath-link,/browser-work/cxx-runtime-threaded/lib:/browser-work/prefix/lib:/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/lib:/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/usr/lib \
 "$@"
SH
cat > "$TASK_WORK/toolchain/browser685-webengine-cxx" <<'SH'
#!/bin/sh
exec /usr/bin/arm-linux-gnueabihf-g++-11 \
 --sysroot=/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot \
 -B/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/usr/lib/ \
 -B/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/lib/ \
 -nostdinc -nostdinc++ \
 -isystem /browser-work/cxx-runtime-threaded/include/c++/11.4.0 \
 -isystem /browser-work/cxx-runtime-threaded/include/c++/11.4.0/arm-linux-gnueabihf \
 -isystem /browser-work/cxx-runtime-threaded/include/c++/11.4.0/backward \
 -isystem /usr/lib/gcc-cross/arm-linux-gnueabihf/11/include \
 -isystem /opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/usr/include \
 -L/browser-work/cxx-runtime-threaded/lib -L/browser-work/prefix/lib \
 -Wl,-rpath-link,/browser-work/cxx-runtime-threaded/lib:/browser-work/prefix/lib:/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/lib:/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/usr/lib \
 "$@"
SH
chmod 755 "$TASK_WORK/toolchain/browser685-webengine-cc" "$TASK_WORK/toolchain/browser685-webengine-cxx"
export PATH="$TASK_WORK/host-tools/bin:$TASK_WORK/host-tools/node/bin:$PATH"
export PKG_CONFIG_PATH=
export PKG_CONFIG_SYSROOT_DIR=
export PKG_CONFIG_LIBDIR="$TASK_WORK/prefix/lib/pkgconfig:$TASK_WORK/prefix/share/pkgconfig"
export NINJAFLAGS="-j$JOBS -l$JOBS"
export CMAKE_BUILD_PARALLEL_LEVEL="$JOBS"
cd "$BUILD"
if [ ! -f build.ninja ]; then
    "$TASK_WORK/target-qt/bin/qt-configure-module" "$TASK_WORK/sources/qtwebengine-6.8.5" -- \
        -DCMAKE_TOOLCHAIN_FILE=/build-defs/armv7-webengine.cmake \
        -DQT_HOST_PATH="$TASK_WORK/host-qt" \
        -DCMAKE_PREFIX_PATH="$TASK_WORK/target-qt;$TASK_WORK/prefix" \
        -DCMAKE_INSTALL_PREFIX=/opt/p011-browser-6.8.5 \
        -DCMAKE_STAGING_PREFIX="$TASK_WORK/target-qt" \
        -DCMAKE_BUILD_TYPE=Release -DQT_BUILD_TESTS=OFF -DQT_BUILD_EXAMPLES=OFF \
        -DGn_EXECUTABLE="$TASK_WORK/host-tools/bin/gn" \
        -DNodejs_EXECUTABLE="$TASK_WORK/host-tools/node/bin/node" \
        -DFEATURE_qtwebengine_build=ON -DFEATURE_qtwebengine_core_build=ON \
        -DFEATURE_qtwebengine_quick_build=ON -DFEATURE_qtwebengine_widgets_build=OFF \
        -DFEATURE_qtpdf_build=OFF -DFEATURE_webengine_jumbo_build=OFF \
        -DFEATURE_webengine_webrtc=OFF -DFEATURE_webengine_printing_and_pdf=OFF \
        -DFEATURE_webengine_spellchecker=OFF -DFEATURE_webengine_pepper_plugins=OFF \
        -DFEATURE_webengine_extensions=OFF -DFEATURE_webengine_ozone_x11=OFF \
        -DFEATURE_webengine_vulkan=OFF -DFEATURE_webengine_vaapi=OFF \
        -DFEATURE_webengine_system_ffmpeg=OFF -DFEATURE_webengine_system_alsa=OFF \
        -DFEATURE_webengine_system_pulseaudio=OFF -DFEATURE_webengine_system_glib=OFF \
        -DFEATURE_webengine_system_gbm=OFF -DFEATURE_webengine_webchannel=ON \
        -DFEATURE_webenginedriver=OFF -DFEATURE_webengine_proprietary_codecs=ON \
        -DEGL_LIBRARY="$TASK_WORK/prefix/lib/libmali.so.0.28.0" \
        -DGLESv2_LIBRARY="$TASK_WORK/prefix/lib/libmali.so.0.28.0" \
        -DEGL_INCLUDE_DIR="$TASK_WORK/prefix/include" \
        -DGLESv2_INCLUDE_DIR="$TASK_WORK/prefix/include"
fi
cmake -S "$TASK_WORK/sources/qtwebengine-6.8.5" -B . \
    -U CMAKE_C_FLAGS -U CMAKE_CXX_FLAGS
# GN's generated argument file is its standard configuration surface. Qt does
# not expose this independent ANGLE backend as a CMake feature. Keep the source
# pristine and apply this one explicit build-local argument after configure.
python3 - "$BUILD" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1]) / 'src/core/Release/arm/args.gn'
text = path.read_text()
rows = [row for row in text.splitlines() if not row.startswith('angle_enable_vulkan=')]
rows.append('angle_enable_vulkan=false')
path.write_text('\n'.join(rows) + '\n')
print('GN_BUILD_LOCAL_OVERRIDE=angle_enable_vulkan=false')
PY
printf 'CHROMIUM_NINJA_LIMIT=jobs%s/load%s\n' "$JOBS" "$JOBS"
cmake --build . --parallel "$JOBS"
cmake --install .
printf 'TARGET_WEBENGINE_READY=%s\n' "$TASK_WORK/target-qt"
