#include "config.h"
#include <Windows.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace wxhelper {
namespace {
std::wstring Environment(const wchar_t* name) {
  const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
  if (!size) return {};
  std::vector<wchar_t> buffer(size);
  const DWORD count = GetEnvironmentVariableW(name, buffer.data(), size);
  if (!count || count >= size) throw std::runtime_error("Environment changed while resolving helper data directory.");
  return std::wstring(buffer.data(), count);
}
}
Config::Config() = default;
Config::~Config() = default;
void Config::Initialize(const std::filesystem::path& directory) {
  auto root = directory;
  if (root.empty()) root = Environment(L"WXHELPER_DATA_DIR");
  if (root.empty()) {
    const auto local = Environment(L"LOCALAPPDATA");
    if (local.empty()) throw std::runtime_error("LOCALAPPDATA is missing; set an absolute WXHELPER_DATA_DIR.");
    root = std::filesystem::path(local) / L"wxhelper";
  }
  if (!root.is_absolute()) throw std::invalid_argument("Helper data directory must be absolute.");
  root = root.lexically_normal();
  std::filesystem::create_directories(root / L"logs");
  const auto config_path = root / L"config.ini";
  wchar_t value[128]{};
  const DWORD count = GetPrivateProfileStringW(L"config", L"Port", L"19088", value, 128, config_path.c_str());
  if (!count || count >= 127) throw std::invalid_argument("Invalid config Port.");
  unsigned int port = 0;
  for (DWORD i = 0; i < count; ++i) {
    if (value[i] < L'0' || value[i] > L'9') throw std::invalid_argument("Port must contain decimal digits only.");
    port = port * 10 + (value[i] - L'0');
    if (port > 65535) throw std::invalid_argument("Port must be between 1 and 65535.");
  }
  if (!port) throw std::invalid_argument("Port must be between 1 and 65535.");
  port_ = static_cast<int>(port);
  config_path_ = config_path;
  log_path_ = root / L"logs" / (L"wxhelper-" + std::to_wstring(GetCurrentProcessId()) + L".log");
}
int Config::GetPort() const { return port_; }
}  // namespace wxhelper
