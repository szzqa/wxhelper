#ifndef GLOBAL_CONTEXT_H_
#define GLOBAL_CONTEXT_H_
#include "config.h"
#include "http_server.h"
#include "log.h"
#include "singleton.h"
#include "manager.h"
#include <atomic>

namespace wxhelper {

enum class GlobalContextState { NOT_INITIALIZED, INITIALIZING, INITIALIZED, FAILED };

class GlobalContext : public Singleton<GlobalContext> {
  friend class Singleton<GlobalContext>;
  ~GlobalContext();

 public:
  // Intentionally process-owned: do not destroy asynchronous resources while
  // the CRT holds the loader lock during process teardown.
  static GlobalContext& GetInstance();
  void initialize(HMODULE module);
  void finally();

 public:
  std::optional<Config> config;
  std::optional<Log> log;
  std::unique_ptr<HttpServer> http_server;
  std::unique_ptr<Manager> mgr;

  std::atomic<GlobalContextState> state{GlobalContextState::NOT_INITIALIZED};

 private:
  HMODULE module_;
};

}  // namespace wxhelper
#endif
