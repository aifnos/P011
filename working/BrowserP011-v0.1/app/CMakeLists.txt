cmake_minimum_required(VERSION 3.21)
project(BrowserP011Probe VERSION 0.1 LANGUAGES CXX)

# Qt itself is built separately against the verified P011 sysroot. This project
# never installs into a system directory and never modifies the factory Qt.
find_package(Qt6 6.8.5 REQUIRED COMPONENTS Core Gui Network Qml Quick WebEngineCore WebEngineQuick)
if(NOT Qt6_VERSION VERSION_LESS "6.9.0")
    message(FATAL_ERROR "This candidate requires the Qt 6.8 graphics path")
endif()
qt_standard_project_setup()
qt_add_executable(p011-browser-probe main.cpp interactive_controller.cpp interactive_controller.h)
target_compile_features(p011-browser-probe PRIVATE cxx_std_17)
target_link_libraries(p011-browser-probe PRIVATE
    Qt6::Core Qt6::Gui Qt6::Network Qt6::Qml Qt6::Quick Qt6::WebEngineCore Qt6::WebEngineQuick)
qt_add_resources(p011-browser-probe probe_resources
    PREFIX "/p011-browser"
    FILES Main.qml home.html public_metrics.js Interactive.qml BrowserButton.qml BrowserKeyboard.qml)
set_target_properties(p011-browser-probe PROPERTIES
    BUILD_RPATH_USE_ORIGIN TRUE
    INSTALL_RPATH "$ORIGIN/../lib")

