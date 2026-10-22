#include "api_validation.h"

#include <charconv>
#include <limits>
#include <map>
#include <utility>
#include <vector>

namespace wxhelper::api {
namespace {

[[noreturn]] void Invalid(const std::string& key, const char* reason) {
  throw Error(400, "invalid_parameter", "parameter '" + key + "' " + reason);
}

const nlohmann::json& Required(const nlohmann::json& object,
                               const std::string& key) {
  if (!object.is_object()) {
    throw Error(400, "invalid_body", "request body must be a JSON object");
  }
  const auto it = object.find(key);
  if (it == object.end()) Invalid(key, "is required");
  return *it;
}

template <typename Integer>
Integer ParseDecimal(const std::string& text, const std::string& key) {
  Integer result{};
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
  if (text.empty() || parsed.ec != std::errc{} ||
      parsed.ptr != text.data() + text.size()) {
    Invalid(key, "must be a decimal integer in range");
  }
  return result;
}

enum class Kind { String, NonEmpty, Csv, Int, Int64, Uint64 };
struct Field {
  const char* name;
  Kind kind;
};

const std::map<std::string_view, std::vector<Field>>& Routes() {
  using K = Kind;
  static const std::map<std::string_view, std::vector<Field>> routes = {
      {"/api/checkLogin", {}},
      {"/api/userInfo", {}},
      {"/api/sendTextMsg", {{"wxid", K::NonEmpty}, {"msg", K::NonEmpty}}},
      {"/api/hookSyncMsg", {{"port", K::Int}, {"ip", K::NonEmpty}, {"enableHttp", K::Int}}},
      {"/api/sendImagesMsg", {{"wxid", K::NonEmpty}, {"imagePath", K::NonEmpty}}},
      {"/api/sendFileMsg", {{"wxid", K::NonEmpty}, {"filePath", K::NonEmpty}}},
      {"/api/getContactList", {}},
      {"/api/unhookSyncMsg", {}},
      {"/api/getDBInfo", {}},
      {"/api/execSql", {{"dbHandle", K::Uint64}, {"sql", K::NonEmpty}}},
      {"/api/getChatRoomDetailInfo", {{"chatRoomId", K::NonEmpty}}},
      {"/api/addMemberToChatRoom", {{"chatRoomId", K::NonEmpty}, {"memberIds", K::Csv}}},
      {"/api/modifyNickname", {{"chatRoomId", K::NonEmpty}, {"wxid", K::NonEmpty}, {"nickName", K::String}}},
      {"/api/delMemberFromChatRoom", {{"chatRoomId", K::NonEmpty}, {"memberIds", K::Csv}}},
      {"/api/getMemberFromChatRoom", {{"chatRoomId", K::NonEmpty}}},
      {"/api/topMsg", {{"msgId", K::Uint64}}},
      {"/api/removeTopMsg", {{"chatRoomId", K::NonEmpty}, {"msgId", K::Uint64}}},
      {"/api/InviteMemberToChatRoom", {{"chatRoomId", K::NonEmpty}, {"memberIds", K::Csv}}},
      {"/api/hookLog", {}},
      {"/api/unhookLog", {}},
      {"/api/createChatRoom", {{"memberIds", K::Csv}}},
      {"/api/quitChatRoom", {{"chatRoomId", K::NonEmpty}}},
      {"/api/forwardMsg", {{"msgId", K::Uint64}, {"wxid", K::NonEmpty}}},
      {"/api/getSNSFirstPage", {}},
      {"/api/getSNSNextPage", {{"snsId", K::Uint64}}},
      {"/api/addFavFromMsg", {{"msgId", K::Uint64}}},
      {"/api/addFavFromImage", {{"wxid", K::NonEmpty}, {"imagePath", K::NonEmpty}}},
      {"/api/sendAtText", {{"chatRoomId", K::NonEmpty}, {"wxids", K::Csv}, {"msg", K::NonEmpty}}},
      {"/api/getContactProfile", {{"wxid", K::NonEmpty}}},
      {"/api/downloadAttach", {{"msgId", K::Uint64}}},
      {"/api/forwardPublicMsg", {{"wxid", K::NonEmpty}, {"appName", K::String}, {"userName", K::String},
                                  {"title", K::String}, {"url", K::NonEmpty}, {"thumbUrl", K::String}, {"digest", K::String}}},
      {"/api/forwardPublicMsgByMsgId", {{"wxid", K::NonEmpty}, {"msgId", K::Uint64}}},
      {"/api/decodeImage", {{"filePath", K::NonEmpty}, {"storeDir", K::NonEmpty}}},
      {"/api/getVoiceByMsgId", {{"msgId", K::Uint64}, {"storeDir", K::NonEmpty}}},
      {"/api/sendCustomEmotion", {{"wxid", K::NonEmpty}, {"filePath", K::NonEmpty}}},
      {"/api/sendApplet", {{"wxid", K::NonEmpty}, {"waidConcat", K::String}, {"waid", K::String},
                            {"appletWxid", K::String}, {"jsonParam", K::String}, {"headImgUrl", K::String},
                            {"mainImg", K::String}, {"indexPage", K::String}}},
      {"/api/sendPatMsg", {{"receiver", K::NonEmpty}, {"wxid", K::NonEmpty}}},
      {"/api/ocr", {{"imagePath", K::NonEmpty}}},
      {"/api/test", {}},
  };
  return routes;
}

void ValidateField(const nlohmann::json& object, const Field& field) {
  switch (field.kind) {
    case Kind::Int: GetInt(object, field.name); return;
    case Kind::Int64: GetInt64(object, field.name); return;
    case Kind::Uint64: GetUint64(object, field.name); return;
    default: break;
  }
  const auto value = GetString(object, field.name);
  if (field.kind == Kind::NonEmpty && value.empty()) {
    Invalid(field.name, "must not be empty");
  }
  if (field.kind == Kind::Csv) {
    // Retain the existing comma-separated string API, not a JSON array.
    std::size_t start = 0;
    do {
      const auto comma = value.find(',', start);
      const auto item = value.substr(start, comma == std::string::npos
                                               ? std::string::npos : comma - start);
      if (item.find_first_not_of(" \t\r\n") == std::string::npos) {
        Invalid(field.name, "must contain nonempty comma-separated IDs");
      }
      if (comma == std::string::npos) break;
      start = comma + 1;
    } while (start <= value.size());
  }
}
}  // namespace

Error::Error(int status, std::string code, std::string message)
    : std::runtime_error(std::move(message)), status_(status), code_(std::move(code)) {}

std::string ErrorBody(int status, const std::string& code, const std::string& message) {
  return nlohmann::json{{"code", status}, {"error", code}, {"msg", message},
                        {"data", nullptr}}.dump();
}

Response ExecuteSafely(const std::function<std::string()>& action) {
  try {
    return {200, action()};
  } catch (const Error& error) {
    return {error.status(), ErrorBody(error.status(), error.code(), error.what())};
  } catch (const std::exception&) {
    return {500, ErrorBody(500, "internal_error", "internal server error")};
  } catch (...) {
    return {500, ErrorBody(500, "internal_error", "internal server error")};
  }
}

std::int64_t GetInt64(const nlohmann::json& object, const std::string& key) {
  const auto& value = Required(object, key);
  if (value.is_number_unsigned()) {
    const auto number = value.get<std::uint64_t>();
    if (number > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)())) {
      Invalid(key, "is outside the signed 64-bit range");
    }
    return static_cast<std::int64_t>(number);
  }
  if (value.is_number_integer()) return value.get<std::int64_t>();
  if (value.is_string()) return ParseDecimal<std::int64_t>(value.get<std::string>(), key);
  Invalid(key, "must be an integer or a decimal integer string");
}

std::uint64_t GetUint64(const nlohmann::json& object, const std::string& key) {
  const auto& value = Required(object, key);
  if (value.is_number_unsigned()) return value.get<std::uint64_t>();
  if (value.is_number_integer()) {
    const auto number = value.get<std::int64_t>();
    if (number < 0) Invalid(key, "must not be negative");
    return static_cast<std::uint64_t>(number);
  }
  if (value.is_string()) return ParseDecimal<std::uint64_t>(value.get<std::string>(), key);
  Invalid(key, "must be an unsigned integer or a decimal integer string");
}

int GetInt(const nlohmann::json& object, const std::string& key) {
  const auto number = GetInt64(object, key);
  if (number < (std::numeric_limits<int>::min)() || number > (std::numeric_limits<int>::max)()) {
    Invalid(key, "is outside the integer range");
  }
  return static_cast<int>(number);
}

std::string GetString(const nlohmann::json& object, const std::string& key) {
  const auto& value = Required(object, key);
  if (!value.is_string()) Invalid(key, "must be a string");
  auto text = value.get<std::string>();
  if (text.find('\0') != std::string::npos) Invalid(key, "must not contain NUL bytes");
  return text;
}

nlohmann::json ValidateRequest(std::string_view method, std::string_view path,
                               std::string_view body) {
  const auto route = Routes().find(path);
  if (route == Routes().end()) throw Error(404, "not_found", "API route not found");
  if (method != "POST") throw Error(405, "method_not_allowed", "use POST for this API route");
  auto object = nlohmann::json::object();
  if (!body.empty()) {
    object = nlohmann::json::parse(body.begin(), body.end(), nullptr, false);
    if (object.is_discarded()) throw Error(400, "invalid_json", "request body is not valid JSON");
  }
  if (!object.is_object()) throw Error(400, "invalid_body", "request body must be a JSON object");
  for (const auto& field : route->second) ValidateField(object, field);
  if (path == "/api/hookSyncMsg") {
    const auto port = GetInt(object, "port");
    if (port < 1 || port > 65535) Invalid("port", "must be in the range 1..65535");
    const auto enable = GetInt(object, "enableHttp");
    if (enable != 0 && enable != 1) Invalid("enableHttp", "must be 0 or 1");
    if (enable == 1) {
      ValidateField(object, {"url", Kind::NonEmpty});
      if (GetInt(object, "timeout") <= 0) Invalid("timeout", "must be positive");
    }
  }
  if (path == "/api/test") {
    throw Error(501, "diagnostic_disabled", "development diagnostic is disabled; use /api/health for readiness");
  }
  return object;
}

nlohmann::json SubmissionResponse(std::int64_t legacy_code) {
  const bool returned = legacy_code == 1;
  nlohmann::json data = {{"status", returned ? "submitted" : "submission_unverified"},
                         {"submitted", nullptr}, {"submissionScope", "native_call_returned"},
                         {"nativeAcceptance", "unverified"}, {"delivery", "unverified"}};
  if (returned) data["submitted"] = true;
  return {{"code", legacy_code}, {"data", data},
          {"msg", returned ? "submitted to native call; delivery unverified"
                            : "submission and delivery unverified"}};
}
}  // namespace wxhelper::api
