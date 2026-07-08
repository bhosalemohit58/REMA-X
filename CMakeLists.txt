cmake_minimum_required(VERSION 3.22)
project(REMA-X VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard to C++23
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add include directory
include_directories(include)

# Add executable
add_executable(remax 
    src/main.cpp
    src/FileLoader.cpp
    src/HeaderParser.cpp
)

# Welcome message
message(STATUS "REMA-X: C++23 Binary Analysis Framework")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
