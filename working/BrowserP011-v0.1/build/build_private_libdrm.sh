#!/bin/sh
set -eu
TASK_WORK=/browser-work
SRC="$TASK_WORK/sources/libdrm-2.4.113"
BUILD="$TASK_WORK/build-libdrm"
test "$(sha256sum /input-downloads/libdrm-2.4.113.tar.xz | cut -d ' ' -f1)" = 7fd7eb2967f63beb4606f22d50e277d993480d05ef75dd88a9bd8e677323e5e1
if [ ! -d "$SRC" ]; then
    tar -xJf /input-downloads/libdrm-2.4.113.tar.xz -C "$TASK_WORK/sources"
fi
if [ ! -d "$TASK_WORK/abi-snapshots/libdrm-device" ]; then
    mkdir -p "$TASK_WORK/abi-snapshots/libdrm-device"
    cp -a "$TASK_WORK"/prefix/lib/libdrm.so* "$TASK_WORK/abi-snapshots/libdrm-device/"
fi
cat > "$TASK_WORK/libdrm-cross.ini" <<'CROSS'
[binaries]
c = '/browser-work/toolchain/browser685-gcc'
ar = '/usr/bin/arm-linux-gnueabihf-ar'
strip = '/usr/bin/arm-linux-gnueabihf-strip'
pkgconfig = '/usr/bin/pkg-config'
[host_machine]
system = 'linux'
cpu_family = 'arm'
cpu = 'armv7'
endian = 'little'
[properties]
needs_exe_wrapper = true
[built-in options]
c_args = ['-march=armv7-a', '-mfpu=neon', '-mfloat-abi=hard']
c_link_args = ['-L/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/lib', '-L/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/usr/lib']
CROSS
if [ ! -f "$BUILD/build.ninja" ]; then
    meson setup "$BUILD" "$SRC" --cross-file "$TASK_WORK/libdrm-cross.ini" \
        --prefix "$TASK_WORK/prefix" --libdir lib --buildtype release \
        -Dintel=disabled -Dradeon=disabled -Damdgpu=disabled -Dnouveau=disabled \
        -Dvmwgfx=disabled -Domap=disabled -Dexynos=disabled -Dfreedreno=disabled \
        -Dtegra=disabled -Dvc4=disabled -Detnaviv=disabled \
        -Dcairo-tests=disabled -Dman-pages=disabled -Dvalgrind=disabled \
        -Dudev=false -Dinstall-test-programs=false
fi
ninja -C "$BUILD" -j4 -l4
python3 - <<'PY'
from pathlib import Path
prefix = Path('/browser-work/prefix/lib')
snapshot = Path('/browser-work/abi-snapshots/libdrm-device')
for name in ['libdrm.so.2', 'libdrm.so']:
    path = prefix / name
    if path.is_file() and not path.is_symlink():
        if not (snapshot / name).is_file() or path.read_bytes() != (snapshot / name).read_bytes():
            raise SystemExit('Unexpected regular DRM alias identity: ' + str(path))
        # The exact original private copy remains in the verified snapshot.
        path.unlink()
PY
meson install -C "$BUILD"
arm-linux-gnueabihf-readelf --version-info "$TASK_WORK/prefix/lib/libdrm.so.2"
cat "$TASK_WORK/prefix/lib/pkgconfig/libdrm.pc"
cp /input-downloads/libdrm-source-lock.json "$TASK_WORK/prefix/libdrm-source-lock.json"
