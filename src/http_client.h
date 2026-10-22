#ifndef WXHELPER_HTTP_CLIENT_H_
#define WXHELPER_HTTP_CLIENT_H_
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include "mongoose.h"
#include "singleton.h"

namespace wxhelper {
enum class HttpRequestStatus {
  Success, NotConfigured, InvalidConfiguration, UnsupportedScheme,
  ConnectFailed, ConnectionError, ClosedWithoutResponse, InvalidResponse,
  HttpError, Timeout, Cancelled
};
struct HttpRequestResult {
  HttpRequestStatus status = HttpRequestStatus::NotConfigured;
  int http_status = 0;
};
const char* HttpRequestStatusName(HttpRequestStatus status);

class HttpClient : public Singleton<HttpClient> {
 public:
  HttpRequestResult SendRequest(std::string content);
  // Plain HTTP only. timeout_ms covers resolving, connecting, sending and
  // waiting for the response. Invalid configuration cancels existing requests.
  bool SetConfig(std::string url, std::uint64_t timeout_ms);

  // Thread-safe and idempotent. Also rejects queued/new requests until a
  // successful SetConfig. The owner must still drain/join its callback pool.
  void CancelPendingRequests();

  static void OnHttpEvent(struct mg_connection *c, int ev, void *ev_data,
                          void *fn_data);
 private:
  std::mutex config_mutex_;
  std::string url_;
  std::string authority_;
  std::string uri_;
  std::uint64_t timeout_ms_ = 0;
  HttpRequestStatus config_status_ = HttpRequestStatus::NotConfigured;
  std::atomic<std::uint64_t> cancellation_epoch_{0};
};

}  // namespace wxhelper
#endif
