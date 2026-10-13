cmake_minimum_required(VERSION 3.21)
project(wxhelper VERSION 1.0.0 LANGUAGES C CXX)

if(NOT WIN32 OR NOT MSVC)
  message(FATAL_ERROR "wxhelper requires Windows and MSVC.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "This branch uses the 3.9.5.81 x64 ABI. Configure with -A x64.")
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_definitions(UNICODE _UNICODE)
add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:/utf-8>)
include(CTest)

add_library(client_compatibility STATIC src/client_compatibility.cc)
target_include_directories(client_compatibility PUBLIC src)
target_link_libraries(client_compatibility PUBLIC version)
add_executable(wxhelper_probe source/client_probe.cc)
target_link_libraries(wxhelper_probe PRIVATE client_compatibility)
add_subdirectory(source)

# Static snapshot decoders only; deliberately separate from the injected DLL.
add_library(weixin4_snapshot STATIC
  src/weixin4/memory_reader.cc src/weixin4/profile.cc
  src/weixin4/contact_backend.cc)
target_include_directories(weixin4_snapshot PUBLIC src)

option(WXHELPER_BUILD_DLL "Build the legacy 3.9.5.81 backend" ON)
if(WXHELPER_BUILD_DLL)
  enable_language(ASM_MASM)
  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/spdlog/CMakeLists.txt")
    message(FATAL_ERROR "Missing spdlog submodule. Run: git submodule update --init spdlog")
  endif()
  add_subdirectory(spdlog)
  set(WXHELPER_JSON_SOURCE_DIR "" CACHE PATH "Optional nlohmann/json source directory")
  if(WXHELPER_JSON_SOURCE_DIR)
    add_subdirectory("${WXHELPER_JSON_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/json")
  else()
    find_package(nlohmann_json CONFIG REQUIRED)
  endif()
  set(WXHELPER_DETOURS_SOURCE_DIR "" CACHE PATH "Optional Microsoft Detours source directory")
  if(WXHELPER_DETOURS_SOURCE_DIR)
    set(detours_src "${WXHELPER_DETOURS_SOURCE_DIR}/src")
    add_library(wxhelper_detours STATIC
      "${detours_src}/detours.cpp" "${detours_src}/modules.cpp"
      "${detours_src}/disasm.cpp" "${detours_src}/image.cpp"
      "${detours_src}/creatwth.cpp" "${detours_src}/disolx86.cpp"
      "${detours_src}/disolx64.cpp" "${detours_src}/disolia64.cpp"
      "${detours_src}/disolarm.cpp" "${detours_src}/disolarm64.cpp")
    target_include_directories(wxhelper_detours PUBLIC "${detours_src}")
    target_compile_definitions(wxhelper_detours PRIVATE WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0601)
  else()
    find_path(DETOURS_INCLUDE_DIR detours.h PATH_SUFFIXES detours REQUIRED)
    find_library(DETOURS_LIBRARY detours REQUIRED)
    add_library(wxhelper_detours UNKNOWN IMPORTED)
    set_target_properties(wxhelper_detours PROPERTIES
      IMPORTED_LOCATION "${DETOURS_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${DETOURS_INCLUDE_DIR}")
  endif()
  file(GLOB CPP_FILES CONFIGURE_DEPENDS src/*.cc src/*.cpp src/*.c)
  list(REMOVE_ITEM CPP_FILES "${CMAKE_CURRENT_SOURCE_DIR}/src/client_compatibility.cc")
  file(GLOB ASM_FILES CONFIGURE_DEPENDS src/*.asm)
  add_library(wxhelper SHARED ${CPP_FILES} ${ASM_FILES})
  target_link_libraries(wxhelper PRIVATE client_compatibility
    nlohmann_json::nlohmann_json spdlog::spdlog wxhelper_detours ws2_32)
  set_target_properties(wxhelper PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
endif()

if(BUILD_TESTING)
  add_executable(weixin4_memory_tests tests/weixin4_memory_tests.cc)
  target_link_libraries(weixin4_memory_tests PRIVATE weixin4_snapshot)
  target_compile_options(weixin4_memory_tests PRIVATE /UNDEBUG)
  add_test(NAME weixin4_memory COMMAND weixin4_memory_tests)
  add_executable(weixin4_contact_tests tests/weixin4_contact_tests.cc)
  target_link_libraries(weixin4_contact_tests PRIVATE weixin4_snapshot)
  target_compile_options(weixin4_contact_tests PRIVATE /UNDEBUG)
  add_test(NAME weixin4_contacts COMMAND weixin4_contact_tests)
  add_executable(wechat_string_test tests/wechat_string_test.cc)
  target_compile_options(wechat_string_test PRIVATE /UNDEBUG)
  add_test(NAME wechat_string COMMAND wechat_string_test)
  add_subdirectory(tests/compatibility)
endif()
