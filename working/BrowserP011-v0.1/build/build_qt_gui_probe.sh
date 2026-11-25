#!/bin/sh
set -eu
TASK_WORK=/browser-work
BUILD="$TASK_WORK/build-qt-gui-probe"
mkdir -p "$BUILD" /gui-output
cat > "$BUILD/CMakeLists.txt" <<'CMAKE'
cmake_minimum_required(VERSION 3.19)
project(P011QtGuiProbe LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
find_package(Qt6 6.8.5 EXACT REQUIRED COMPONENTS Gui)
add_executable(p011-browser-gui-probe /build-defs/qt_gui_probe.cpp)
target_link_libraries(p011-browser-gui-probe PRIVATE Qt6::Gui)
set_target_properties(p011-browser-gui-probe PROPERTIES INSTALL_RPATH "$ORIGIN/../lib")
install(TARGETS p011-browser-gui-probe RUNTIME DESTINATION bin)
CMAKE
cmake -G Ninja -S "$BUILD" -B "$BUILD" -U HAVE_EGL -U HAVE_GLESv2 \
    -DCMAKE_TOOLCHAIN_FILE=/build-defs/armv7-qt6.cmake \
    -DQT_HOST_PATH="$TASK_WORK/host-qt" \
    -DCMAKE_PREFIX_PATH="$TASK_WORK/target-qt;$TASK_WORK/prefix" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/gui-output \
    -DCMAKE_BUILD_RPATH_USE_ORIGIN=ON \
    -DEGL_LIBRARY="$TASK_WORK/prefix/lib/libmali.so.0.28.0" \
    -DGLESv2_LIBRARY="$TASK_WORK/prefix/lib/libmali.so.0.28.0" \
    -DEGL_INCLUDE_DIR="$TASK_WORK/prefix/include" \
    -DGLESv2_INCLUDE_DIR="$TASK_WORK/prefix/include"
cmake --build "$BUILD" --parallel 4
cmake --install "$BUILD"
python3 /build-defs/package_gui_probe.py
