#!/bin/sh
# Build in a fresh explicit container directory; no device access in this script.
set -eu
root=${1:?usage: build_p2p_private.sh /work/mta-p2p-build-UNIQUE}
case "$root" in /work/mta-p2p-build-*) ;; *) echo 'Refusing build root' >&2; exit 2 ;; esac
case "$root" in *'..'*|*' '*|*'//'*) echo 'Invalid build root' >&2; exit 2 ;; esac
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$root"
cd "$root"
if [ ! -f wpa_supplicant-2.12.tar.gz ]; then
 curl -fsSL --max-time 40 https://w1.fi/releases/wpa_supplicant-2.12.tar.gz -o wpa_supplicant-2.12.tar.gz
fi
if [ ! -f libnl-3.11.0.tar.gz ]; then
 curl -fsSL --max-time 40 https://github.com/thom311/libnl/releases/download/libnl3_11_0/libnl-3.11.0.tar.gz -o libnl-3.11.0.tar.gz
fi
# SHA-256 values captured from fixed official HTTPS release URLs on 2026-09-30.
# These are reproducibility pins, not a claim of detached-signature verification.
printf '%s\n' \
 '08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6  wpa_supplicant-2.12.tar.gz' \
 '2a56e1edefa3e68a7c00879496736fdbf62fc94ed3232c0baba127ecfa76874d  libnl-3.11.0.tar.gz' | sha256sum -c -
if [ -e .mta-build-started ]; then echo 'Use a fresh build root; no overwriting candidates' >&2; exit 2; fi
touch .mta-build-started
tar -xzf libnl-3.11.0.tar.gz
tar -xzf wpa_supplicant-2.12.tar.gz
cd libnl-3.11.0
# Static project-built libnl; target libc comes from the old P011 SDK.
./configure --host=arm-buildroot-linux-gnueabihf --prefix="$root/prefix" \
 --disable-shared --enable-static --disable-cli --disable-pthreads \
 CC=arm-buildroot-linux-gnueabihf-gcc AR=arm-buildroot-linux-gnueabihf-ar \
 CFLAGS='-Os -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -D_GNU_SOURCE -include time.h' \
 YACC=/usr/bin/bison
make -j2
make install
cd "$root/wpa_supplicant-2.12"
patch -p1 --fuzz=0 < "$here/p2p-private-initial-mode.patch"
cp "$here/p2p-private.config" wpa_supplicant/.config
cd wpa_supplicant
CFLAGS="-Os -fstack-protector-strong -D_FORTIFY_SOURCE=2 -I$root/prefix/include/libnl3" \
LIBS="-L$root/prefix/lib" \
make -j2 wpa_supplicant wpa_cli \
 CC=arm-buildroot-linux-gnueabihf-gcc \
 PKG_CONFIG="env PKG_CONFIG_LIBDIR=$root/prefix/lib/pkgconfig /usr/bin/pkg-config"
mkdir -p "$root/output/licenses"
cp wpa_supplicant "$root/output/mta-wpa-supplicant"
cp wpa_cli "$root/output/mta-wpa-cli"
cp "$root/wpa_supplicant-2.12/COPYING" "$root/output/licenses/wpa-COPYING"
cp "$root/libnl-3.11.0/COPYING" "$root/output/licenses/libnl-COPYING"
cp "$here/p2p-private-initial-mode.patch" "$root/output/licenses/project-wpa-modification.patch"
mkdir -p "$root/output/source" "$root/output/relink"
cp "$root/wpa_supplicant-2.12.tar.gz" "$root/libnl-3.11.0.tar.gz" "$root/output/source/"
cp "$here/p2p-private.config" "$here/build_p2p_private.sh" "$root/output/source/"
cp "$here/p2p-private-initial-mode.patch" "$root/output/source/"
# Static LGPL libnl: provide corresponding sources and application objects for relinking.
tar -czf "$root/output/relink/wpa-application-objects.tar.gz" -C "$root/wpa_supplicant-2.12" build
cp "$root/libnl-3.11.0/lib/.libs/libnl-3.a" "$root/libnl-3.11.0/lib/.libs/libnl-genl-3.a" "$root/output/relink/"
arm-buildroot-linux-gnueabihf-readelf -d "$root/output/mta-wpa-supplicant"
sha256sum "$root/output/mta-wpa-supplicant" "$root/output/mta-wpa-cli"
