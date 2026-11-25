#!/bin/sh
set -eu
TASK_WORK=${P011_BROWSER_WORK:-/browser-work}
OLD_SYSROOT=/opt/p011/sdk/arm-buildroot-linux-gnueabihf/sysroot
CXX_PREFIX="$TASK_WORK/cxx-runtime-threaded"
OUT=/abi-output
mkdir -p "$OUT/lib"
if [ -f "$OUT/manifest.json" ]; then
    history="$OUT/history/$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$history"
    cp "$OUT/manifest.json" "$OUT/browser685-abi-probe" "$OUT/probe-elf.txt" "$history/"
fi
arm-linux-gnueabihf-g++-11 \
    --sysroot="$OLD_SYSROOT" -B"$OLD_SYSROOT/usr/lib/" -B"$OLD_SYSROOT/lib/" \
    -std=c++17 -O2 -pthread -march=armv7-a -mfpu=neon -mfloat-abi=hard \
    -nostdinc -nostdinc++ \
    -isystem "$CXX_PREFIX/include/c++/11.4.0" \
    -isystem "$CXX_PREFIX/include/c++/11.4.0/arm-linux-gnueabihf" \
    -isystem "$CXX_PREFIX/include/c++/11.4.0/backward" \
    -isystem /usr/lib/gcc-cross/arm-linux-gnueabihf/11/include \
    -isystem "$OLD_SYSROOT/usr/include" \
    /build-defs/abi_probe.cpp -o "$OUT/browser685-abi-probe" \
    -L"$CXX_PREFIX/lib" -L"$OLD_SYSROOT/lib" -L"$OLD_SYSROOT/usr/lib" \
    -Wl,--no-undefined -Wl,-rpath-link,"$CXX_PREFIX/lib:$OLD_SYSROOT/lib:$OLD_SYSROOT/usr/lib" \
    -Wl,-rpath,'$ORIGIN/lib' -Wl,--dynamic-linker=/lib/ld-linux-armhf.so.3
cp -L "$CXX_PREFIX/lib/libstdc++.so.6" "$OUT/lib/libstdc++.so.6"
cp -L "$CXX_PREFIX/lib/libgcc_s.so.1" "$OUT/lib/libgcc_s.so.1"
arm-linux-gnueabihf-strip --strip-unneeded "$OUT/browser685-abi-probe" "$OUT/lib/libstdc++.so.6" "$OUT/lib/libgcc_s.so.1"
arm-linux-gnueabihf-readelf -h -l -d --version-info "$OUT/browser685-abi-probe" > "$OUT/probe-elf.txt"
grep -q 'Shared library: \[libstdc++.so.6\]' "$OUT/probe-elf.txt"
arm-linux-gnueabihf-readelf -d --version-info "$OUT/lib/libstdc++.so.6" > "$OUT/libstdcxx-elf.txt"
python3 - <<'PY'
import hashlib, json, pathlib, re, subprocess
out = pathlib.Path('/abi-output')
files = {}
for name in ['browser685-abi-probe', 'lib/libstdc++.so.6', 'lib/libgcc_s.so.1']:
    path = out / name
    body = path.read_bytes()
    versions = subprocess.check_output(['arm-linux-gnueabihf-readelf','--version-info',str(path)], text=True)
    required = sorted(set(re.findall(r'\bGLIBC_([0-9.]+)', versions)), key=lambda s: tuple(map(int,s.split('.'))))
    if any(tuple(map(int,v.split('.'))) > (2,27) for v in required):
        raise SystemExit('GLIBC gate failed for ' + name)
    files[name] = dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest(), required_glibc=required)
(out / 'manifest.json').write_text(json.dumps(dict(schema=1, status='HOST_ARM_LINK_PASS_DEVICE_PENDING',
    compiler='Ubuntu cross GCC 11.4.0', target='ARMv7 hard-float', sysroot_glibc='2.27',
    libstdcxx='GCC 11.4.0 rebuilt against old sysroot with POSIX gthreads', libgcc='Original Bootlin GCC 8.2 SDK runtime',
    source_sha256=hashlib.sha256(pathlib.Path('/build-defs/abi_probe.cpp').read_bytes()).hexdigest(),
    no_network=True, device_tested=False, files=files), indent=2))
print((out / 'manifest.json').read_text())
PY
