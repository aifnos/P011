FROM p011-bili-builder:abi227

# Keep the vendor-compatible Bootlin glibc 2.27 sysroot.  Only the host cross
# compiler is newer; target C++ runtime is rebuilt by prepare_cxx_runtime.sh.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-11-arm-linux-gnueabihf g++-11-arm-linux-gnueabihf \
    binutils-arm-linux-gnueabihf build-essential cmake ninja-build \
    pkg-config python3 python3-html5lib gperf bison flex perl git curl \
    ca-certificates xz-utils file patch autoconf automake libtool \
    libfontconfig1-dev libdbus-1-dev libnss3-dev libnspr4-dev \
    libwayland-dev wayland-protocols libxkbcommon-dev libffi-dev \
    libegl1-mesa-dev libgles2-mesa-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/local/bin:/usr/bin:/bin:/opt/p011/sdk/bin"
WORKDIR /browser-work
