#!/bin/sh
# Run inside the new browser builder, with a fresh writable /browser-work.
# The old Bili volume is never needed writable.
set -eu

TASK_WORK=${P011_BROWSER_WORK:-/browser-work}
OLD_SYSROOT=/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot
GCC_VERSION=11.4.0
TARGET_PREFIX="$TASK_WORK/cxx-runtime-threaded"
BUILD_DIR="$TASK_WORK/build-libstdcxx-$GCC_VERSION-threads"
SOURCE_DIR="$TASK_WORK/sources/gcc-$GCC_VERSION"
mkdir -p "$TASK_WORK/downloads" "$TASK_WORK/sources" "$BUILD_DIR" "$TARGET_PREFIX"

if [ ! -f "$SOURCE_DIR/libstdc++-v3/configure" ]; then
    curl -fL --retry 3 "https://ftp.gnu.org/gnu/gcc/gcc-$GCC_VERSION/gcc-$GCC_VERSION.tar.xz" \
        -o "$TASK_WORK/downloads/gcc-$GCC_VERSION.tar.xz"
    sha256sum "$TASK_WORK/downloads/gcc-$GCC_VERSION.tar.xz" > "$TASK_WORK/downloads/gcc-$GCC_VERSION.tar.xz.sha256.observed"
    tar -xJf "$TASK_WORK/downloads/gcc-$GCC_VERSION.tar.xz" -C "$TASK_WORK/sources"
fi

# Standalone libstdc++ expects this generated libgcc header in the sibling
# build directory. Without it, configure silently disables gthreads even
# though the cross compiler reports the posix thread model.
mkdir -p "$TASK_WORK/libgcc"
cp "$SOURCE_DIR/libgcc/gthr-posix.h" "$TASK_WORK/libgcc/gthr-default.h"

# -B forces old glibc startup objects ahead of the distribution cross sysroot.
# Target libstdc++ is built standalone, not the complete GCC compiler.
export CC="arm-linux-gnueabihf-gcc-11 --sysroot=$OLD_SYSROOT -B$OLD_SYSROOT/usr/lib/ -B$OLD_SYSROOT/lib/"
export CXX="arm-linux-gnueabihf-g++-11 --sysroot=$OLD_SYSROOT -B$OLD_SYSROOT/usr/lib/ -B$OLD_SYSROOT/lib/"
export AR=arm-linux-gnueabihf-ar
export RANLIB=arm-linux-gnueabihf-ranlib
export CFLAGS="-O2 -march=armv7-a -mfpu=neon -mfloat-abi=hard -nostdinc -isystem /usr/lib/gcc-cross/arm-linux-gnueabihf/11/include -isystem $OLD_SYSROOT/usr/include"
export CXXFLAGS="$CFLAGS"
export LDFLAGS="--sysroot=$OLD_SYSROOT -L$OLD_SYSROOT/lib -L$OLD_SYSROOT/usr/lib -Wl,-rpath-link,$OLD_SYSROOT/lib:$OLD_SYSROOT/usr/lib"
cd "$BUILD_DIR"
if [ ! -f Makefile ]; then
    "$SOURCE_DIR/libstdc++-v3/configure" \
        --build=x86_64-linux-gnu --host=arm-linux-gnueabihf \
        --prefix="$TARGET_PREFIX" --libdir="$TARGET_PREFIX/lib" \
        --with-gxx-include-dir="$TARGET_PREFIX/include/c++/$GCC_VERSION" \
        --with-sysroot="$OLD_SYSROOT" --disable-multilib --disable-nls \
        --disable-libstdcxx-pch --enable-shared --disable-static \
        --enable-libstdcxx-threads --enable-libstdcxx-time
fi
make -j"${P011_BUILD_JOBS:-4}"
make install
grep -q '^#define _GLIBCXX_HAS_GTHREADS 1' "$TARGET_PREFIX/include/c++/$GCC_VERSION/arm-linux-gnueabihf/bits/c++config.h"

# Keep the known old ABI libgcc instead of accidentally shipping the apt one.
# This is admissible only if real ARM linking resolves every required GCC_*
# symbol; the cross-link probe and final ELF checks must verify this.
cp -L "$OLD_SYSROOT/lib/libgcc_s.so.1" "$TARGET_PREFIX/lib/libgcc_s.so.1"
ln -sfn libgcc_s.so.1 "$TARGET_PREFIX/lib/libgcc_s.so"
printf 'CXX_RUNTIME=%s\n' "$TARGET_PREFIX"
arm-linux-gnueabihf-readelf --version-info "$TARGET_PREFIX/lib/libstdc++.so.6" \
    | grep -o 'GLIBC_[0-9.]*' | sort -Vu
