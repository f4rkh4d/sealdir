cmake_minimum_required(VERSION 3.20)
project(sealdir VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Wpedantic)
# sodium + fuse come in a later commit.
add_library(sealdir_base STATIC src/base64url.cpp)
target_include_directories(sealdir_base PUBLIC include)
