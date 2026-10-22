add_library(client_fixture SHARED fixture.cc current.rc)
set_target_properties(client_fixture PROPERTIES OUTPUT_NAME Weixin)
add_library(legacy_fixture SHARED fixture.cc legacy.rc)
set_target_properties(legacy_fixture PROPERTIES OUTPUT_NAME WeChatWin)
add_executable(compatibility_test compatibility_test.cc)
target_link_libraries(compatibility_test PRIVATE client_compatibility)
add_test(NAME client_compatibility COMMAND compatibility_test
  "$<TARGET_FILE:client_fixture>" "$<TARGET_FILE:legacy_fixture>")
if(TARGET wxhelper)
  add_executable(reject_client_test reject_client_test.cc)
  add_test(NAME reject_current_client COMMAND reject_client_test
    "$<TARGET_FILE:client_fixture>" "$<TARGET_FILE:wxhelper>")
  set_tests_properties(reject_current_client PROPERTIES TIMEOUT 10)
  add_executable(startup_lifetime_test startup_lifetime_test.cc)
  target_compile_definitions(startup_lifetime_test PRIVATE NOMINMAX)
  target_link_libraries(startup_lifetime_test PRIVATE ws2_32 nlohmann_json::nlohmann_json)
  add_test(NAME startup_lifetime COMMAND startup_lifetime_test
    "$<TARGET_FILE:legacy_fixture>" "$<TARGET_FILE:wxhelper>"
    "${CMAKE_BINARY_DIR}/startup-artifacts")
  set_tests_properties(startup_lifetime PROPERTIES TIMEOUT 30)
endif()
