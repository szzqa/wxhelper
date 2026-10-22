#ifndef GLOBAL_CONTEXT_H_
#define GLOBAL_CONTEXT_H_
#include "config.h"
#include "http_server.h"
#include "log.h"
#include "singleton.h"
#include "manager.h"
#include <atomic>
#include <mutex>

namespace wxhelper {

enum class GlobalContextState { NOT_INITIALIZED, INITIALIZING, INITIALIZED, FAILED,
                                STOPPING, STOPPED, STOP_FAILED };

class GlobalContext : public Singleton<GlobalContext> {
  friend class Singleton<GlobalContext>;
  ~GlobalContext();

 public:
  // Intentionally process-owned: do not destroy asynchronous resources while
  // the CRT holds the loader lock during process teardown.
  static GlobalContext& GetInstance();
  void initialize(HMODULE module);
  void finally();
  nlohmann::json Health();
  nlohmann::json Capabilities();
  bool PrepareStop();
  void FinishStopAsync();

 public:
  std::optional<Config> config;
  std::optional<Log> log;
  std::unique_ptr<HttpServer> http_server;
  std::unique_ptr<Manager> mgr;

  std::atomic<GlobalContextState> state{GlobalContextState::NOT_INITIALIZED};

 private:
  void RecordFailure(const std::string& error, GlobalContextState failed_state);
  HMODULE module_ = nullptr;
  std::mutex status_mutex_;
  std::mutex stop_mutex_;
  std::string client_version_, config_path_, log_path_, error_;
  std::atomic<bool> stop_worker_started_{false};
};

}  // namespace wxhelper
#endif
