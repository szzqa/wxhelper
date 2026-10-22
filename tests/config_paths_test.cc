#include "config.h"
#include <Windows.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#ifdef WXHELPER_TEST_LOG
#include "log.h"
#include "spdlog/spdlog.h"
#endif
namespace fs = std::filesystem;
void Check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
int main() {
  const auto root = fs::temp_directory_path() / (L"wxhelper-config-测试-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
  try {
    fs::create_directories(root);
    wxhelper::Config config;
    config.Initialize(root);
    Check(config.GetPort() == 19088, "default port");
    Check(config.GetConfigPath() == root / L"config.ini", "absolute config path");
    Check(config.GetLogPath().parent_path() == root / L"logs", "log directory");
    Check(config.GetLogPath().filename().wstring().find(std::to_wstring(GetCurrentProcessId())) != std::wstring::npos, "per-process log");
#ifdef WXHELPER_TEST_LOG
    wxhelper::Log log;
    log.Initialize(config.GetLogPath());
    spdlog::info("Unicode runtime directory test");
    Check(fs::file_size(config.GetLogPath()) > 0, "log not written at configured Unicode path");
#endif
    const auto file = config.GetConfigPath();
    Check(WritePrivateProfileStringW(L"config", L"Port", L"19442", file.c_str()) != 0, "write test config");
    const auto old_cwd = fs::current_path();
    fs::current_path(root.parent_path());
    config.Initialize(root);
    fs::current_path(old_cwd);
    Check(config.GetPort() == 19442, "port independent of working directory");
    for (const auto* invalid : {L"0", L"65536", L"-1", L"123junk", L"9999999999999999999999999999"}) {
      WritePrivateProfileStringW(L"config", L"Port", invalid, file.c_str());
      bool rejected = false;
      try { config.Initialize(root); } catch (const std::invalid_argument&) { rejected = true; }
      Check(rejected, "invalid port accepted");
    }
    bool rejected = false;
    try { config.Initialize(L"relative-path"); } catch (const std::invalid_argument&) { rejected = true; }
    Check(rejected, "relative directory accepted");
    // Keep owned artifacts for inspection; no caller paths are removed.
    std::cout << "Config absolute paths, Unicode, CWD independence and invalid ports: PASS\n";
    return 0;
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
