cmake_minimum_required(VERSION 3.21)

project(windows_agent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(windows_agent
    src/main.cpp
    src/inventory.cpp
)

target_link_libraries(windows_agent
    user32
)
