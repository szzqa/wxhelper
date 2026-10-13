#include "pch.h"
#include "http_server_callback.h"
#include "http_server.h"

namespace wxhelper {

HttpServer::HttpServer(int port)
    : port_(port), running_(false), mgr_{}, thread_(nullptr) {
  mg_mgr_init(&mgr_);
}

HttpServer::~HttpServer() {
  HttpClose();
}

bool HttpServer::HttpStart() {
  std::lock_guard<std::mutex> lock(lifecycle_mutex_);
  if (running_.load()) {
    return true;
  }
  // A failed join must not allow another worker to use the same manager.
  if (thread_ != nullptr) {
    return false;
  }
  if (port_ < 1 || port_ > 65535) {
    SPDLOG_ERROR("Invalid HTTP server port: {}", port_);
    return false;
  }
  const std::string listen_addr = "http://127.0.0.1:" + std::to_string(port_);
  if (mg_http_listen(&mgr_, listen_addr.c_str(), EventHandler, &mgr_) == nullptr) {
    SPDLOG_ERROR("HTTP server listen failed on port {}", port_);
    return false;
  }
#ifdef _DEBUG
  Utils::CreateConsole();
#endif
  running_.store(true);
  thread_ = CreateThread(nullptr, 0, StartHttpServer, this, 0, nullptr);
  if (thread_ == nullptr) {
    const DWORD error = GetLastError();
    running_.store(false);
    mg_mgr_free(&mgr_);
#ifdef _DEBUG
    Utils::CloseConsole();
#endif
    SPDLOG_ERROR("HTTP server thread creation failed: {}", error);
    return false;
  }
  return true;
}

bool HttpServer::HttpClose() {
  std::lock_guard<std::mutex> lock(lifecycle_mutex_);
  running_.store(false);
  if (thread_ != nullptr) {
    if (WaitForSingleObject(thread_, INFINITE) != WAIT_OBJECT_0) {
      SPDLOG_ERROR("Waiting for HTTP server thread failed: {}", GetLastError());
      return false;
    }
    CloseHandle(thread_);
    thread_ = nullptr;
#ifdef _DEBUG
    Utils::CloseConsole();
#endif
  }
  // The worker has exited, so the manager and its listening socket can now
  // be released safely. A subsequent start can reuse the empty manager.
  mg_mgr_free(&mgr_);
  return true;
}

int HttpServer::GetPort() { return port_; }
bool HttpServer::GetRunning() { return running_.load(); }

const mg_mgr* HttpServer::GetMgr() { return &mgr_; }

}  // namespace wxhelper
