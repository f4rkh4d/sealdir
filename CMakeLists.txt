cmake_minimum_required(VERSION 3.20)
project(sealdir VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Wpedantic)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
add_library(sealdir_lib STATIC
  src/base64url.cpp
  src/crypto.cpp
  src/header.cpp
  src/vault.cpp
  src/password.cpp
)
target_include_directories(sealdir_lib PUBLIC include ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sealdir_lib PUBLIC ${SODIUM_LIBRARIES})
