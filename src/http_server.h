#ifndef WXHELPER_HTTP_SERVER_H_
#define WXHELPER_HTTP_SERVER_H_

#include <atomic>
#include <mutex>

#include "mongoose.h"

namespace wxhelper {
class HttpServer {
 public:
  explicit HttpServer(int port);
  HttpServer(const HttpServer&) = delete;
  HttpServer(HttpServer &&)=delete;
   HttpServer& operator=(const HttpServer&) = delete;
  ~HttpServer();

  bool HttpStart();
  bool HttpClose();
  int  GetPort();
  bool GetRunning();
  const mg_mgr* GetMgr();

 private:
  int port_;
  std::atomic<bool> running_;
  struct mg_mgr mgr_;
  HANDLE thread_;
  std::mutex lifecycle_mutex_;
};
}  // namespace wxhelper

#endif
