#include "pch.h"
#include "global_context.h"
#include "thread_pool.h"
#include "db.h"
#include "client_compatibility.h"
#include "hooks.h"
#include "http_client.h"

namespace wxhelper {
namespace {
const char* StateName(GlobalContextState state) {
  switch (state) {
    case GlobalContextState::NOT_INITIALIZED: return "not_initialized";
    case GlobalContextState::INITIALIZING: return "initializing";
    case GlobalContextState::INITIALIZED: return "ready";
    case GlobalContextState::FAILED: return "failed";
    case GlobalContextState::STOPPING: return "stopping";
    case GlobalContextState::STOPPED: return "stopped";
    case GlobalContextState::STOP_FAILED: return "stop_failed";
  }
  return "unknown";
}
}

GlobalContext& GlobalContext::GetInstance() {
  static GlobalContext* instance = new GlobalContext();
  return *instance;
}

GlobalContext::~GlobalContext() {
  if (config.has_value()) {
    config.reset();
  }
  if (log.has_value()) {
    log.reset();
  }
  
}
void GlobalContext::initialize(HMODULE module) {
  state = GlobalContextState::INITIALIZING;
  try {
    module_ = module;
    const auto client = InspectLoadedClient();
    if (!client.supported) {
      throw std::runtime_error("Unsupported WeChat client; no offsets were called.");
    }
    UINT64 base = reinterpret_cast<UINT64>(client.module);
    config.emplace();
    config->Initialize();
    log.emplace();
    log->Initialize(config->GetLogPath());
    {
      std::lock_guard<std::mutex> lock(status_mutex_);
      client_version_ = Utils::WstringToUTF8(client.version);
      config_path_ = config->GetConfigPath().u8string();
      log_path_ = config->GetLogPath().u8string();
      error_.clear();
    }
    // Publish diagnostics before native backend setup. Business dispatch checks
    // INITIALIZED before reading mgr; a setup failure leaves diagnostics alive.
    http_server = std::make_unique<HttpServer>(config->GetPort());
    if (!http_server->HttpStart()) {
      throw std::runtime_error("Failed to start wxhelper HTTP server.");
    }
    if (!ThreadPool::GetInstance().Create(2, 8)) {
      throw std::runtime_error("Failed to create wxhelper thread pool.");
    }
    mgr = std::make_unique<Manager>(base);
    DB::GetInstance().init(base);
    state = GlobalContextState::INITIALIZED;
  } catch (const std::exception& error) {
    RecordFailure(error.what(), GlobalContextState::FAILED);
    throw;
  } catch (...) {
    RecordFailure("Unknown initialization failure", GlobalContextState::FAILED);
    throw;
  }
}

void GlobalContext::finally() {
  try {
    const int hook_error = hooks::StopAll();
    if (hook_error != ERROR_SUCCESS) {
      throw std::runtime_error("Cannot detach hooks; retry stop. Windows error " + std::to_string(hook_error));
    }
    HttpClient::GetInstance().CancelPendingRequests();
    if (!ThreadPool::GetInstance().Stop()) {
      throw std::runtime_error("Cannot drain the callback pool; retry stop.");
    }
    if (http_server && !http_server->HttpClose()) {
      throw std::runtime_error("Cannot close the HTTP worker; restart the host.");
    }
    std::lock_guard<std::mutex> lock(stop_mutex_);
    state = GlobalContextState::STOPPED;
  } catch (const std::exception& error) {
    std::lock_guard<std::mutex> lock(stop_mutex_);
    RecordFailure(error.what(), GlobalContextState::STOP_FAILED);
    stop_worker_started_.store(false);
  } catch (...) {
    std::lock_guard<std::mutex> lock(stop_mutex_);
    RecordFailure("Unknown stop failure", GlobalContextState::STOP_FAILED);
    stop_worker_started_.store(false);
  }
}

void GlobalContext::RecordFailure(const std::string& error, GlobalContextState failed_state) {
  std::lock_guard<std::mutex> lock(status_mutex_);
  error_ = error;
  state = failed_state;
  OutputDebugStringA(error.c_str());
}

nlohmann::json GlobalContext::Health() {
  std::lock_guard<std::mutex> lock(status_mutex_);
  const auto current = state.load();
  return {{"code", 0}, {"msg", "success"}, {"data", {
      {"state", StateName(current)}, {"ready", current == GlobalContextState::INITIALIZED},
      {"backend", "legacy_3.9.5.81_x64"}, {"clientVersion", client_version_},
      {"configPath", config_path_}, {"logPath", log_path_}, {"error", error_},
      {"dllPinned", true}, {"stopSupported", true}, {"dynamicUnload", false}}}};
}

nlohmann::json GlobalContext::Capabilities() {
  const bool ready = state.load() == GlobalContextState::INITIALIZED;
  return {{"code", 0}, {"msg", "success"}, {"data", {
      {"backend", "legacy_3.9.5.81_x64"}, {"ready", ready},
      {"login", ready}, {"contacts", ready}, {"sendText", ready},
      {"receiveHook", ready}, {"deliveryConfirmation", false},
      {"weixin4Runtime", false}, {"health", true}, {"stop", true},
      {"dynamicUnload", false}}}};
}

bool GlobalContext::PrepareStop() {
  std::lock_guard<std::mutex> lock(stop_mutex_);
  auto current = state.load();
  for (;;) {
    if (current == GlobalContextState::STOPPING || current == GlobalContextState::STOPPED) return true;
    if (current == GlobalContextState::INITIALIZING || current == GlobalContextState::NOT_INITIALIZED) return false;
    if (state.compare_exchange_weak(current, GlobalContextState::STOPPING)) return true;
  }
}

void GlobalContext::FinishStopAsync() {
  std::lock_guard<std::mutex> lock(stop_mutex_);
  if (state.load() != GlobalContextState::STOPPING) return;
  bool expected = false;
  if (!stop_worker_started_.compare_exchange_strong(expected, true)) return;
  HANDLE worker = CreateThread(nullptr, 0, [](LPVOID opaque) -> DWORD {
    static_cast<GlobalContext*>(opaque)->finally();
    return 0;
  }, this, 0, nullptr);
  if (worker) {
    CloseHandle(worker);
  } else {
    stop_worker_started_.store(false);
    RecordFailure("Cannot create stop worker; retry stop.", GlobalContextState::STOP_FAILED);
  }
}
}  // namespace wxhelper
