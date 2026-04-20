include(FetchContent)
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG v3.5.3
)
FetchContent_MakeAvailable(Catch2)

add_executable(sealdir_tests
  crypto_test.cpp
  filename_test.cpp
  header_test.cpp
  vault_test.cpp
)
target_link_libraries(sealdir_tests PRIVATE sealdir_core Catch2::Catch2WithMain)
# tests live under tests/ so we can disable -Werror for fetched catch2 noise if needed.
target_compile_options(sealdir_tests PRIVATE -Wall -Wextra)

include(CTest)
include(Catch)
catch_discover_tests(sealdir_tests)
