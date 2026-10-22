#ifndef WXHELPER_API_VALIDATION_H_
#define WXHELPER_API_VALIDATION_H_

#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace wxhelper::api {

class Error : public std::runtime_error {
 public:
  Error(int status, std::string code, std::string message);
  int status() const noexcept { return status_; }
  const std::string& code() const noexcept { return code_; }

 private:
  int status_;
  std::string code_;
};

struct Response {
  int status;
  std::string body;
};

std::string ErrorBody(int status, const std::string& code,
                      const std::string& message);
Response ExecuteSafely(const std::function<std::string()>& action);

// Validates the entire request before the caller can enter a native backend.
// Empty bodies are treated as {} for the legacy parameterless POST routes.
nlohmann::json ValidateRequest(std::string_view method, std::string_view path,
                               std::string_view body);

int GetInt(const nlohmann::json& object, const std::string& key);
std::int64_t GetInt64(const nlohmann::json& object, const std::string& key);
std::uint64_t GetUint64(const nlohmann::json& object, const std::string& key);
std::string GetString(const nlohmann::json& object, const std::string& key);

// Legacy code 1 says only that the wrapper returned after calling native code.
// Neither native acceptance nor eventual delivery has been established.
nlohmann::json SubmissionResponse(std::int64_t legacy_code);

}  // namespace wxhelper::api
#endif
