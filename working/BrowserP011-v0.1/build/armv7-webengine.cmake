# Chromium's GN toolchain uses compiler paths directly, outside CMake flags.
# These wrappers keep all Chromium translation units on the old target ABI.
include(/build-defs/armv7-qt6.cmake)
# The wrappers supply the real --sysroot. Leaving CMAKE_SYSROOT set makes GN's
# pkg-config.py prepend it to already absolute private-prefix dependency paths.
# Root-path discovery stays constrained by CMAKE_FIND_ROOT_PATH from the base.
set(CMAKE_SYSROOT "")
set(CMAKE_C_COMPILER /browser-work/toolchain/browser685-webengine-cc)
set(CMAKE_CXX_COMPILER /browser-work/toolchain/browser685-webengine-cxx)
# The pinned Chromium FFmpeg ARM configuration requires Thumb-2. This remains
# ARMv7 hard-float and interoperates with the ARM-mode Qt shared libraries.
string(APPEND CMAKE_C_FLAGS_INIT " -mthumb")
string(APPEND CMAKE_CXX_FLAGS_INIT " -mthumb")
