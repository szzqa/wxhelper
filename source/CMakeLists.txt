cmake_minimum_required(VERSION 3.15)
project(injector VERSION 1.0.0 LANGUAGES CXX)

if(NOT WIN32 OR NOT MSVC)
  message(FATAL_ERROR "The injector requires Windows and MSVC.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "This wxhelper branch requires a 64-bit injector; configure with -A x64.")
endif()

add_executable(injector injector.cc)
target_compile_features(injector PRIVATE cxx_std_17)
target_compile_definitions(injector PRIVATE UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS)
target_compile_options(injector PRIVATE /utf-8)
target_link_libraries(injector PRIVATE advapi32)
set_target_properties(injector PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)

option(WXHELPER_INJECTOR_TESTS "Build isolated injector fixtures (never uses WeChat)" OFF)
if(WXHELPER_INJECTOR_TESTS)
  enable_testing()
  add_executable(injector_test_target tests/injection_target.cc)
  add_library(injector_test_accept SHARED tests/injection_fixture.cc)
  add_library(injector_test_reject SHARED tests/injection_fixture.cc)
  target_compile_definitions(injector_test_reject PRIVATE REJECT_ON_ATTACH)
  add_test(NAME injector_smoke COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass
    -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/injector_smoke.ps1"
    -Injector "$<TARGET_FILE:injector>"
    -Target "$<TARGET_FILE:injector_test_target>"
    -AcceptedDll "$<TARGET_FILE:injector_test_accept>"
    -RejectedDll "$<TARGET_FILE:injector_test_reject>")
  set_tests_properties(injector_smoke PROPERTIES TIMEOUT 45)
endif()
