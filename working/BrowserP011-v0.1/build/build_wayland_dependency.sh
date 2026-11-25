#!/bin/sh
set -eu
TASK_WORK=/browser-work
PREFIX="$TASK_WORK/prefix"
SYSROOT=/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot
export CC="arm-linux-gnueabihf-gcc-11 --sysroot=$SYSROOT -B$SYSROOT/usr/lib/ -B$SYSROOT/lib/"
export CFLAGS="-O2 -fPIC -march=armv7-a -mfpu=neon -mfloat-abi=hard -nostdinc -isystem /usr/lib/gcc-cross/arm-linux-gnueabihf/11/include -isystem $SYSROOT/usr/include -I$PREFIX/include"
export LDFLAGS="-L$PREFIX/lib -L$SYSROOT/lib -L$SYSROOT/usr/lib -Wl,-rpath-link,$PREFIX/lib:$SYSROOT/lib:$SYSROOT/usr/lib"
export PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig:$PREFIX/share/pkgconfig"
export PKG_CONFIG_PATH=
mkdir -p "$TASK_WORK/sources" "$TASK_WORK/build-libffi"
if [ ! -f "$TASK_WORK/sources/libffi-3.2.1/configure" ]; then
    tar -xzf /input-downloads/libffi-3.2.1.tar.gz -C "$TASK_WORK/sources"
fi
cd "$TASK_WORK/build-libffi"
if [ ! -f Makefile ]; then
    "$TASK_WORK/sources/libffi-3.2.1/configure" --host=arm-linux-gnueabihf \
        --build=x86_64-linux-gnu --prefix="$PREFIX" --disable-static --disable-docs
fi
make -j"${P011_BUILD_JOBS:-4}"
make install

if [ ! -f "$TASK_WORK/sources/wayland-1.20.0/meson.build" ]; then
    tar -xJf /input-downloads/wayland-1.20.0.tar.xz -C "$TASK_WORK/sources"
fi
python3 - <<'PY'
import pathlib
wrapper = pathlib.Path('/browser-work/toolchain/browser685-gcc')
wrapper.parent.mkdir(parents=True, exist_ok=True)
wrapper.write_text('''#!/bin/sh
exec arm-linux-gnueabihf-gcc-11 --sysroot=/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot -B/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/usr/lib/ -B/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/lib/ -nostdinc -isystem /usr/lib/gcc-cross/arm-linux-gnueabihf/11/include -isystem /opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/usr/include "$@"
''')
wrapper.chmod(0o755)
p = pathlib.Path('/browser-work/wayland-cross.ini')
p.write_text('''[binaries]
c = '/browser-work/toolchain/browser685-gcc'
ar = 'arm-linux-gnueabihf-ar'
strip = 'arm-linux-gnueabihf-strip'
pkg-config = '/usr/bin/pkg-config'
[host_machine]
system = 'linux'
cpu_family = 'arm'
cpu = 'armv7'
endian = 'little'
[properties]
needs_exe_wrapper = true
pkg_config_libdir = '/browser-work/prefix/lib/pkgconfig'
[built-in options]
prefix = '/browser-work/prefix'
libdir = 'lib'
buildtype = 'release'
c_args = ['-march=armv7-a', '-mfpu=neon', '-mfloat-abi=hard', '-I/browser-work/prefix/include']
c_link_args = ['-L/browser-work/prefix/lib', '-L/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/lib', '-L/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/usr/lib', '-Wl,-rpath-link,/browser-work/prefix/lib:/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/lib:/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot/usr/lib']
''')
PY
unset CC CFLAGS CXXFLAGS LDFLAGS
if [ ! -x "$TASK_WORK/host-tools/bin/wayland-scanner" ]; then
    env -u PKG_CONFIG_LIBDIR -u PKG_CONFIG_PATH meson setup \
        "$TASK_WORK/build-wayland-scanner-host" "$TASK_WORK/sources/wayland-1.20.0" \
        --prefix "$TASK_WORK/host-tools" -Ddocumentation=false -Dtests=false \
        -Dscanner=true -Dlibraries=false -Ddtd_validation=false
    meson compile -C "$TASK_WORK/build-wayland-scanner-host" -j "${P011_BUILD_JOBS:-4}"
    meson install -C "$TASK_WORK/build-wayland-scanner-host"
fi
export PKG_CONFIG_PATH_FOR_BUILD="$TASK_WORK/host-tools/share/pkgconfig:$TASK_WORK/host-tools/lib/pkgconfig:$TASK_WORK/host-tools/lib/x86_64-linux-gnu/pkgconfig"
export PKG_CONFIG_LIBDIR_FOR_BUILD="$PKG_CONFIG_PATH_FOR_BUILD:/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/share/pkgconfig"
if [ ! -f "$TASK_WORK/build-wayland-v7/build.ninja" ]; then
    meson setup "$TASK_WORK/build-wayland-v7" "$TASK_WORK/sources/wayland-1.20.0" \
        --cross-file "$TASK_WORK/wayland-cross.ini" -Ddocumentation=false -Dtests=false -Dscanner=false
fi
meson compile -C "$TASK_WORK/build-wayland-v7" -j "${P011_BUILD_JOBS:-4}"
meson install -C "$TASK_WORK/build-wayland-v7"
printf 'PRIVATE_WAYLAND_READY\n'
