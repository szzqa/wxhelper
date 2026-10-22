#include "api_validation.h"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace api = wxhelper::api;
using nlohmann::json;

#define CHECK(condition) do { if (!(condition)) { \
  std::cerr << "check failed at line " << __LINE__ << ": " #condition << '\n'; \
  std::exit(1); } } while (false)

int backend_calls = 0;
api::Response Request(const std::string& method, const std::string& path,
                       const std::string& body) {
  return api::ExecuteSafely([&] {
    const auto parameters = api::ValidateRequest(method, path, body);
    ++backend_calls;  // Fake backend, no Windows or WeChat dependency.
    return json{{"code", 1}, {"data", parameters}}.dump();
  });
}

void Rejected(const std::string& method, const std::string& path,
              const std::string& body, int status) {
  const auto before = backend_calls;
  const auto response = Request(method, path, body);
  CHECK(response.status == status);
  const auto parsed = json::parse(response.body);
  CHECK(parsed["code"] == status);
  CHECK(parsed["error"].is_string());
  CHECK(parsed["data"].is_null());
  CHECK(backend_calls == before);
}

template <typename Action>
void InvalidNumber(Action action) {
  const auto response = api::ExecuteSafely([&] { action(); return "{}"; });
  CHECK(response.status == 400);
}

void TestRequestBoundary() {
  CHECK(Request("POST", "/api/checkLogin", "").status == 200);
  CHECK(Request("POST", "/api/userInfo", "{}").status == 200);
  for (const auto* method : {"GET", "PUT", "PATCH", "DELETE", "OPTIONS", "post"}) {
    Rejected(method, "/api/sendTextMsg", "{}", 405);
  }
  Rejected("POST", "/api/noSuchRoute", "{}", 404);
  Rejected("POST", "/api/sendTextMsg/extra", "{}", 404);
  Rejected("POST", "/api/inviteMemberToChatRoom", "{}", 404);  // Case matters.
  for (const auto* body : {"[", "{bad}", "null", "[]", "true", "1", "\"text\""}) {
    Rejected("POST", "/api/checkLogin", body, 400);
  }
  Rejected("POST", "/api/sendTextMsg", "", 400);
  Rejected("POST", "/api/sendTextMsg", R"({"wxid":"peer"})", 400);
  Rejected("POST", "/api/sendTextMsg", R"({"wxid":null,"msg":"text"})", 400);
  Rejected("POST", "/api/sendTextMsg", R"({"wxid":"peer","msg":false})", 400);
  Rejected("POST", "/api/sendTextMsg", R"({"wxid":"peer","msg":""})", 400);
  Rejected("POST", "/api/sendTextMsg", R"({"wxid":"peer","msg":"a\u0000b"})", 400);
  CHECK(Request("POST", "/api/sendTextMsg", R"({"wxid":"peer","msg":"\u4f60\u597d"})").status == 200);
  CHECK(Request("POST", "/api/modifyNickname",
                R"({"chatRoomId":"room","wxid":"peer","nickName":""})").status == 200);
  Rejected("POST", "/api/test", "{}", 501);
  Rejected("POST", "/api/test", "", 501);
  Rejected("GET", "/api/test", "", 405);
}

void TestNumbers() {
  constexpr auto u64max = (std::numeric_limits<std::uint64_t>::max)();
  constexpr auto i64max = (std::numeric_limits<std::int64_t>::max)();
  constexpr auto i64min = (std::numeric_limits<std::int64_t>::min)();
  CHECK(api::GetUint64(json{{"value", u64max}}, "value") == u64max);
  CHECK(api::GetUint64(json{{"value", "18446744073709551615"}}, "value") == u64max);
  CHECK(api::GetInt64(json{{"value", i64max}}, "value") == i64max);
  CHECK(api::GetInt64(json{{"value", "9223372036854775807"}}, "value") == i64max);
  CHECK(api::GetInt64(json{{"value", "-9223372036854775808"}}, "value") == i64min);
  CHECK(api::GetInt64(json{{"value", i64min}}, "value") == i64min);
  CHECK(api::GetInt(json{{"value", "2147483647"}}, "value") == 2147483647);
  CHECK(api::GetInt(json{{"value", "-2147483648"}}, "value") == (-2147483647 - 1));
  for (const auto& value : std::vector<json>{true, false, nullptr, 1.0, 1.5,
       "", " ", " 1", "1 ", "+1", "1x", "1.0", "1e2", "--1", "-", json::array()}) {
    InvalidNumber([&] { api::GetInt64(json{{"value", value}}, "value"); });
    InvalidNumber([&] { api::GetUint64(json{{"value", value}}, "value"); });
  }
  for (const auto& value : std::vector<json>{-1, "-1", "-0", "18446744073709551616"}) {
    InvalidNumber([&] { api::GetUint64(json{{"value", value}}, "value"); });
  }
  for (const auto& value : std::vector<json>{u64max, "9223372036854775808", "-9223372036854775809"}) {
    InvalidNumber([&] { api::GetInt64(json{{"value", value}}, "value"); });
  }
  for (const auto& value : std::vector<json>{2147483648LL, -2147483649LL, "2147483648", "-2147483649"}) {
    InvalidNumber([&] { api::GetInt(json{{"value", value}}, "value"); });
  }
  InvalidNumber([&] { api::GetUint64(json::object(), "missing"); });
  const auto wide = api::ValidateRequest("POST", "/api/execSql",
      R"({"dbHandle":18446744073709551615,"sql":"select 1"})");
  CHECK(api::GetUint64(wide, "dbHandle") == u64max);
  // All three former signed routes call unsigned Manager methods. No wraparound.
  for (const auto* route : {"/api/topMsg", "/api/removeTopMsg", "/api/forwardMsg"}) {
    Rejected("POST", route, R"({"msgId":-1,"chatRoomId":"room","wxid":"peer"})", 400);
    CHECK(Request("POST", route,
        R"({"msgId":"18446744073709551615","chatRoomId":"room","wxid":"peer"})").status == 200);
  }
  Rejected("POST", "/api/getSNSNextPage", R"({"snsId":18446744073709551616})", 400);
}

void TestConditionalParametersAndLists() {
  CHECK(Request("POST", "/api/hookSyncMsg",
      R"({"ip":"127.0.0.1","port":"19099","enableHttp":"0"})").status == 200);
  CHECK(Request("POST", "/api/hookSyncMsg",
      R"({"ip":"127.0.0.1","port":65535,"enableHttp":1,"url":"http://localhost/callback","timeout":1000})").status == 200);
  for (const auto& port : std::vector<json>{0, -1, 65536, "999999999999999999999999", true, 12.5}) {
    Rejected("POST", "/api/hookSyncMsg",
        json{{"ip", "127.0.0.1"}, {"port", port}, {"enableHttp", 0}}.dump(), 400);
  }
  for (const auto& enable : std::vector<json>{-1, 2, true, "not a number"}) {
    Rejected("POST", "/api/hookSyncMsg",
        json{{"ip", "127.0.0.1"}, {"port", 80}, {"enableHttp", enable}}.dump(), 400);
  }
  Rejected("POST", "/api/hookSyncMsg", R"({"ip":"local","port":80,"enableHttp":1})", 400);
  Rejected("POST", "/api/hookSyncMsg", R"({"ip":"local","port":80,"enableHttp":1,"url":"http://local"})", 400);
  Rejected("POST", "/api/hookSyncMsg", R"({"ip":"local","port":80,"enableHttp":1,"url":"http://local","timeout":-1})", 400);
  CHECK(Request("POST", "/api/createChatRoom", R"({"memberIds":"one,two"})").status == 200);
  for (const auto& members : std::vector<json>{"", ",", "one,", ",one", "one,,two", "one, ", json::array({"one"}), 1}) {
    Rejected("POST", "/api/createChatRoom", json{{"memberIds", members}}.dump(), 400);
  }
  CHECK(Request("POST", "/api/InviteMemberToChatRoom",
      R"({"chatRoomId":"room","memberIds":"one,two"})").status == 200);
}

void TestErrorsAndSubmissionSemantics() {
  auto response = api::ExecuteSafely([]() -> std::string {
    throw api::Error(503, "backend_unavailable", "native backend is not ready");
  });
  CHECK(response.status == 503);
  CHECK(json::parse(response.body)["code"] == 503);
  response = api::ExecuteSafely([]() -> std::string {
    throw std::out_of_range("private backend diagnostic");
  });
  CHECK(response.status == 500);
  CHECK(response.body.find("private backend diagnostic") == std::string::npos);
  CHECK(json::parse(response.body)["code"] == 500);
  response = api::ExecuteSafely([]() -> std::string { throw 1; });
  CHECK(response.status == 500);
  response = api::ExecuteSafely([] { return json::array().at(1).dump(); });
  CHECK(response.status == 500);  // Unexpected JSON/backend failures are internal.
  const auto submitted = api::SubmissionResponse(1);
  CHECK(submitted["code"] == 1);
  CHECK(submitted["data"]["submitted"] == true);
  CHECK(submitted["data"]["status"] == "submitted");
  CHECK(submitted["data"]["submissionScope"] == "native_call_returned");
  CHECK(submitted["data"]["nativeAcceptance"] == "unverified");
  CHECK(submitted["data"]["delivery"] == "unverified");
  CHECK(submitted["msg"] != "success");
  for (const auto code : {-1, 0, 2}) {
    const auto other = api::SubmissionResponse(code);
    CHECK(other["code"] == code);
    CHECK(other["data"]["submitted"].is_null());
    CHECK(other["data"]["delivery"] == "unverified");
  }
}

int main() {
  TestRequestBoundary();
  TestNumbers();
  TestConditionalParametersAndLists();
  TestErrorsAndSubmissionSemantics();
  std::cout << "API validation tests passed (fake backend only)\n";
}
