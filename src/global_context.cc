#include "pch.h"
#include "global_context.h"
#include "thread_pool.h"
#include "db.h"
#include "client_compatibility.h"

namespace wxhelper {

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
    log->Initialize();
    if (!ThreadPool::GetInstance().Create(2, 8)) {
      throw std::runtime_error("Failed to create wxhelper thread pool.");
    }
    mgr = std::make_unique<Manager>(base);
    DB::GetInstance().init(base);
    // Publish requests only after all dependencies are ready.
    http_server = std::make_unique<HttpServer>(config->GetPort());
    if (!http_server->HttpStart()) {
      throw std::runtime_error("Failed to start wxhelper HTTP server.");
    }
    state = GlobalContextState::INITIALIZED;
  } catch (...) {
    state = GlobalContextState::FAILED;
    throw;
  }
}

void GlobalContext::finally() {
  if (http_server) {
    http_server->HttpClose();
  }
}
}  // namespace wxhelper
