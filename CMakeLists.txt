cmake_minimum_required(VERSION 3.20)
project(sealdir VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

add_compile_options(-Wall -Wextra -Werror -Wpedantic)

find_package(PkgConfig REQUIRED)

# libsodium: try pkg-config, fall back to find_library
pkg_check_modules(SODIUM libsodium)
if(NOT SODIUM_FOUND)
  find_path(SODIUM_INCLUDE_DIR sodium.h
    HINTS /opt/homebrew/include /usr/local/include /usr/include)
  find_library(SODIUM_LIBRARY sodium
    HINTS /opt/homebrew/lib /usr/local/lib /usr/lib)
  if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium not found; install libsodium-dev (linux) or brew install libsodium (macos)")
  endif()
  set(SODIUM_INCLUDE_DIRS "${SODIUM_INCLUDE_DIR}")
  set(SODIUM_LIBRARIES "${SODIUM_LIBRARY}")
endif()

# fuse: linux uses fuse3, macos uses fuse (macfuse). optional for core lib build.
set(SEALDIR_HAVE_FUSE FALSE)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  pkg_check_modules(FUSE fuse3)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  pkg_check_modules(FUSE fuse)
endif()
if(FUSE_FOUND)
  set(SEALDIR_HAVE_FUSE TRUE)
  message(STATUS "fuse found: ${FUSE_VERSION}")
else()
  message(WARNING "fuse not found; building core library + tests only. mount/unmount subcommands will not be built.")
endif()

# core library (no fuse dep)
set(SEALDIR_CORE_SOURCES
  src/crypto.cpp
  src/header.cpp
  src/vault.cpp
  src/password.cpp
  src/base64url.cpp
)

add_library(sealdir_core STATIC ${SEALDIR_CORE_SOURCES})
target_include_directories(sealdir_core PUBLIC
  ${CMAKE_SOURCE_DIR}/include
  ${SODIUM_INCLUDE_DIRS}
)
target_link_libraries(sealdir_core PUBLIC ${SODIUM_LIBRARIES})
target_link_directories(sealdir_core PUBLIC ${SODIUM_LIBRARY_DIRS})

# cli binary. fs.cpp is only compiled when fuse is present.
if(SEALDIR_HAVE_FUSE)
  add_executable(sealdir src/main.cpp src/cli.cpp src/fs.cpp)
  target_compile_definitions(sealdir PRIVATE SEALDIR_HAVE_FUSE=1)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(sealdir PRIVATE FUSE_USE_VERSION=31)
  else()
    target_compile_definitions(sealdir PRIVATE FUSE_USE_VERSION=29 _FILE_OFFSET_BITS=64)
  endif()
  target_include_directories(sealdir PRIVATE ${FUSE_INCLUDE_DIRS})
  target_link_libraries(sealdir PRIVATE sealdir_core ${FUSE_LIBRARIES})
  target_link_directories(sealdir PRIVATE ${FUSE_LIBRARY_DIRS})
  target_compile_options(sealdir PRIVATE ${FUSE_CFLAGS_OTHER})
else()
  add_executable(sealdir src/main.cpp src/cli.cpp)
  target_link_libraries(sealdir PRIVATE sealdir_core)
endif()

enable_testing()
add_subdirectory(tests)
