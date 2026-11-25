# Qt 6.8.5 browser cross-build preparation

This directory owns only host build definitions. It does not run ADB or modify
the original Bili container/volume, vendor files, or device services.

## Verified starting point

- Existing image: `p011-bili-builder:abi227`, image prefix `db2af23faa95`.
- Existing compiler: Bootlin GCC 8.2, ARMv7 hard-float, glibc 2.27. It is too old
  for Qt WebEngine 6.8.5, whose configure check requires GCC 10 or later.
- Existing volume: `p011-bili-build-20260923`; use only read-only when looking up
  dependency sources/libraries. It contains Wayland 1.14 sources/libraries,
  freetype, harfbuzz, OpenSSL and other media dependencies, but no Qt source
  cache was observed in the bounded inspection.
- Pin Qt sources to official `v6.8.5-lts-lgpl`; pin Qt WebEngine to official
  `v6.8.5-lts-lgpl`, Chromium base 122.0.6261.171.

## Immediate commands (new image and new work root only)

From `D:\project\P011`:

```powershell
docker build --progress=plain -t browser685-builder:gcc11 working/BrowserP011-v0.1/build
docker run --rm --name browser685-cxx-runtime --cpus 8 --memory 10g --mount type=volume,source=browser685-build-20261020,target=/browser-work --mount type=bind,source=D:\project\P011\working\BrowserP011-v0.1\build,target=/build-defs,readonly browser685-builder:gcc11 sh /build-defs/prepare_cxx_runtime.sh
```

`prepare_cxx_runtime.sh` rebuilds only GCC 11.4 libstdc++, not the full compiler.
It uses the old glibc 2.27 sysroot and old startup objects. The old libgcc is
copied to the new private prefix and must pass real ARM link/symbol checks.
If any needed GCC runtime symbol is missing, stop and rebuild target libgcc;
do not substitute a new-glibc apt runtime silently.

## Remaining gates before Qt target configure

1. Build a small C++20 ARM executable using the toolchain and new libstdc++.
   Inspect ELF machine, interpreter, NEEDED and symbol-version requirements.
   Every new shipped runtime must require GLIBC no newer than 2.27.
2. Populate the new private dependency prefix with the vendor EGL/GLES link
   stubs, headers and matching runtime identities; never distribute vendor
   libraries. The cached vendor prefix has EGL/GLES headers and libraries.
3. Obtain target headers/libraries for required D-Bus, Fontconfig, NSS/NSPR,
   Wayland client and xkbcommon. Existing private-linksysroot is partial and
   does not contain all these development packages. Host apt headers are not
   automatically valid target development packages.
4. Build native Qt host tools and the target Qt base/declarative/wayland/
   shadertools/webchannel modules in separate directories. WebEngine cannot
   load inside the original Qt 5.10 process.
5. Configure target WebEngine using its Qt 6.8.5 target `qt-configure-module`,
   the native host tools, and `armv7-qt6.cmake`. Keep system FFmpeg off initially
   to use the pinned Chromium FFmpeg, and disable optional WebRTC, printing,
   PDF, spellchecker, WebEngine widgets and X11 on the first candidate.

The actual new work volume is `browser685-build-20261020:/browser-work` and
the actual image is `browser685-builder:gcc11`. Large Windows downloads,
separate raw logs and exported probes are in `E:\P011-browser-build`.
The Docker volume occupies Docker Desktop's VHD on C:, so monitor free space
before the WebEngine compile; this is not an E: storage allocation.
The existing Bili volume remains read-only.
Final configure arguments depend on observed target dependency identities;
these files deliberately do not treat an unrun configure as a successful build.

## Actual progress on 2026-10-20

- The current compiler image is `browser685-builder:gcc11-v8headers`; its
  parents `browser685-builder:gcc11-v8host` and `browser685-builder:gcc11`
  remain available. The final layer exposes existing host x86 Linux UAPI
  headers to the 32-bit V8 build helper; ARM still uses the old explicit
  sysroot and `-nostdinc`.
- Host Qt 6.8.5 tools and the exact-version host GN have built successfully.
- `cxx-runtime-threaded` rebuilds GCC 11.4 libstdc++ with POSIX gthreads. The
  dynamic ARM thread/future/async probe passed on the physical P011 under
  UID 65534; the root agent owns those device logs. This proves the new C++
  runtime ABI and threading probe, not Qt WebEngine.
- Target Qtbase and QtWayland, including the old `wl-shell` integration,
  built and installed into the private staging prefix. The separate MODULE
  linker flags also bind plugins to the private libstdc++.
- The finite frameless Qt GUI probe is exported to
  `E:\P011-browser-build\gui-probe-frameless`. Its 16.03 MiB manifest passed
  host ARM ELF/dependency checks. The root agent subsequently verified on P011
  that UID 65534/GID 44 creates a Wayland/wl-shell surface and a Mali-T820
  OpenGL ES 3.2 context, makes it current, and calls swap with GL error 0.
  Physical scanout and WebEngine are separate acceptance stages. GID 65534
  fails EGL initialization; no driver/account/device-node change was needed.
- Target ShaderTools, Declarative, and WebChannel are installed. Controls uses
  only the Basic style. WebEngine is configured and compiled separately.
- Public NSS 3.35/NSPR 4.19 headers now match the verified device libraries,
  using official Mozilla sources and published SHA256SUMS. The earlier host
  development header snapshots remain preserved in the new work prefix.
- Private libdrm 2.4.113 is built against the old ABI with matching source
  headers/pkg-config metadata. The device library copy is preserved under the
  new work volume's `abi-snapshots`; no device library has been changed.
  Its integration with the complete browser remains a device acceptance item.
- `armv7-webengine.cmake` uses compiler wrappers so Chromium's direct GN
  compilation cannot silently fall back to the apt glibc 2.35 headers/runtime.
  Its CMake sysroot variable is empty only to prevent GN pkg-config from
  rebasing absolute private-prefix paths; the wrappers still pass the actual
  old sysroot to every target compiler invocation. Target pkg-config paths
  are explicit. Actual GN arguments confirm ARMv7 Thumb-2 and NEON.
- Chromium's nested Ninja is explicitly bounded (initially `-j4 -l4`, then
  `-j8 -l8`, currently `-j12 -l12` under a 12 CPU / 10 GiB limit), Release,
  symbol level 0, jumbo disabled. The active object tree is the volume's
  `/browser-work/build-target-qtwebengine` on Linux ext4 to avoid Windows 9P
  metadata delays. Completed host object directories were archived to E:,
  SHA-256 verified and tar-compared before their original objects were
  released. Host Qt installation, sources and target artifacts remain.
  The Docker work volume itself is still stored on C:.
- The current compiler is daemon-owned and detached. A separate hidden
  collector binds its exact container ID, follows raw Docker streams and
  records `docker wait`'s actual build exit. A stopped host client does not
  mean that the compiler stopped. Intentional Ninja interrupts for a
  resource-limit change are recorded separately from compiler failures.
- `package_browser.py` exports only ordinary SONAME files, recursive ELF
  dependencies, actual Qt QML modules/resources, en-US locale, reviewed bounded
  helpers, source locks, and notices. It rejects GLIBC requirements newer than
  2.27 and any font file. A preferred 250 MiB budget is reported; the root
  controller enforces the actual device free-space reserve before upload.

Every build attempt has separate `stdout.raw`, `stderr.raw`, `command.json`,
and `result.json` under `E:\P011-browser-build\logs`. Earlier failures remain
unchanged; success is established only by the later completed attempt.

## New-kernel attempt cancelled on 2026-10-20

The user chose the existing browser kernel instead of continuing Qt 6.
The exact `browser685-webengine` container
`17d15a49dd53eca1de8a6759e93a18b1904fcd6f4a967057b4013fc9d8eb69b5`
was stopped by SIGINT to its verified nested Ninja PID 157/start ticks 349081.
The container is retained in `exited` state. The independent collector saved
the complete raw streams and actual build exit 1 under
`E:\P011-browser-build\logs\20261020-130401-207821-qt-target-webengine-v9-j12-detached`.
Before the interrupt, the raw stream had already recorded `cc1plus` killed;
the final Docker state also reports `OOMKilled=true`. That failure and the
user's cancellation are separate facts. Qt WebEngine did not finish, and no
Qt 6 browser application/runtime package was produced. Sources, tools,
completed objects, archives, logs and the verified Qt GUI probe are preserved.
No further Qt 6 build or packaging proceeds under this cancelled attempt.
