cmake_minimum_required(VERSION 3.21)

project(windows_agent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(windows_agent
    src/main.cpp
    src/scanners/registry_scanner.cpp
    src/scanners/autorun_scanner.cpp
    src/scanners/filesystem_scanner.cpp
    src/scanners/os_catalog_scanner.cpp
    src/scanners/persistence_scanner.cpp
    src/scanners/service_scanner.cpp
    src/scanners/scanner_factory.cpp
    src/orchestration/scan_menu.cpp
    src/helper/normalizer.cpp
    src/helper/json_exporter.cpp
)

if (WIN32)
    target_link_libraries(windows_agent PRIVATE user32)
endif()
