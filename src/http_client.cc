#include "http_client.h"

#include <chrono>
#include <limits>
#include <utility>

namespace wxhelper {
namespace {
constexpr int kPollMilliseconds = 20;

struct RequestData {
  bool done = false;
  bool closed = false;
  bool final_chunk = false;
  std::string url;
  std::string authority;
  std::string uri;
  std::string body;
  std::string content_length;
  std::uint64_t timeout_ms = 0;
  std::uint64_t epoch = 0;
  const std::atomic<std::uint64_t>* cancellation_epoch = nullptr;
  std::chrono::steady_clock::time_point started;
  HttpRequestResult result{HttpRequestStatus::ConnectionError, 0};
};

void Finish(RequestData& data, HttpRequestStatus status, int http_status = 0) {
  if (!data.done) {
    data.result = {status, http_status};
    data.done = true;
  }
}

bool CheckDeadlineAndCancellation(RequestData& data) {
  if (data.done) return true;
  if (data.cancellation_epoch->load() != data.epoch) {
    Finish(data, HttpRequestStatus::Cancelled);
  } else {
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - data.started).count();
    if (static_cast<std::uint64_t>(elapsed) >= data.timeout_ms)
      Finish(data, HttpRequestStatus::Timeout);
  }
  return data.done;
}

bool Decimal(const char* text, std::size_t size, std::uint64_t& value) {
  value = 0;
  if (size == 0) return false;
  for (std::size_t i = 0; i < size; ++i) {
    if (text[i] < '0' || text[i] > '9') return false;
    const auto digit = static_cast<std::uint64_t>(text[i] - '0');
    if (value > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10)
      return false;
    value = value * 10 + digit;
  }
  return true;
}

HttpRequestStatus ParseUrl(const std::string& url, std::string& authority,
                           std::string& uri) {
  if (url.compare(0, 7, "http://") != 0) return HttpRequestStatus::UnsupportedScheme;
  for (const unsigned char c : url)
    if (c <= 0x20 || c == 0x7f || c == '#') return HttpRequestStatus::InvalidConfiguration;
  const auto end = url.find_first_of("/?", 7);
  authority = url.substr(7, end == std::string::npos ? end : end - 7);
  if (authority.empty() || authority.find('@') != std::string::npos)
    return HttpRequestStatus::InvalidConfiguration;
  std::size_t port_position = std::string::npos;
  if (authority.front() == '[') {
    const auto closing = authority.find(']');
    if (closing == std::string::npos || closing == 1) return HttpRequestStatus::InvalidConfiguration;
    if (closing + 1 < authority.size()) {
      if (authority[closing + 1] != ':') return HttpRequestStatus::InvalidConfiguration;
      port_position = closing + 2;
    }
  } else {
    const auto colon = authority.find(':');
    if (colon == 0 || (colon != std::string::npos && authority.find(':', colon + 1) != std::string::npos))
      return HttpRequestStatus::InvalidConfiguration;
    if (colon != std::string::npos) port_position = colon + 1;
  }
  if (port_position != std::string::npos) {
    std::uint64_t port = 0;
    if (!Decimal(authority.data() + port_position, authority.size() - port_position, port) ||
        port == 0 || port > 65535) return HttpRequestStatus::InvalidConfiguration;
  }
  uri = end == std::string::npos ? "/" : url.substr(end);
  if (uri.front() == '?') uri.insert(uri.begin(), '/');
  return HttpRequestStatus::Success;
}
}  // namespace

HttpRequestResult HttpClient::SendRequest(std::string content) {
  RequestData data;
  {
    std::lock_guard<std::mutex> lock(config_mutex_);
    if (config_status_ != HttpRequestStatus::Success) return {config_status_, 0};
    data.url = url_;
    data.authority = authority_;
    data.uri = uri_;
    data.timeout_ms = timeout_ms_;
    data.epoch = cancellation_epoch_.load();
  }
  data.cancellation_epoch = &cancellation_epoch_;
  data.started = std::chrono::steady_clock::now();
  data.body = std::move(content);
  data.content_length = std::to_string(data.body.size());
  if (CheckDeadlineAndCancellation(data)) return data.result;

  mg_mgr manager{};
  mg_mgr_init(&manager);
  if (mg_http_connect(&manager, data.url.c_str(), OnHttpEvent, &data) == nullptr)
    Finish(data, HttpRequestStatus::ConnectFailed);
  while (!CheckDeadlineAndCancellation(data)) {
    mg_mgr_poll(&manager, kPollMilliseconds);
    // The user CLOSE event precedes Mongoose's protocol handler, which may
    // still deliver a complete close-delimited response during this poll.
    if (data.closed) Finish(data, HttpRequestStatus::ClosedWithoutResponse);
  }
  // CLOSE callbacks see the same still-live data object and cannot overwrite
  // the result. Only this request's thread owns its Mongoose manager.
  mg_mgr_free(&manager);
  return data.result;
}

void HttpClient::OnHttpEvent(mg_connection* connection, int event,
                             void* event_data, void* fn_data) {
  auto& data = *static_cast<RequestData*>(fn_data);
  if (CheckDeadlineAndCancellation(data)) {
    connection->is_closing = 1;
    return;
  }
  if (event == MG_EV_CONNECT) {
    if (mg_printf(connection,
                  "POST %s HTTP/1.1\r\nHost: %s\r\n"
                  "Content-Type: application/json\r\nContent-Length: %s\r\n"
                  "Connection: close\r\n\r\n",
                  data.uri.c_str(), data.authority.c_str(), data.content_length.c_str()) == 0 ||
        (!data.body.empty() && !mg_send(connection, data.body.data(), data.body.size()))) {
      Finish(data, HttpRequestStatus::ConnectionError);
    }
  } else if (event == MG_EV_HTTP_CHUNK) {
    auto* message = static_cast<mg_http_message*>(event_data);
    if (message->chunk.len == 0) data.final_chunk = true;
  } else if (event == MG_EV_HTTP_MSG) {
    auto* message = static_cast<mg_http_message*>(event_data);
    const int status = mg_http_status(message);
    if (status >= 100 && status < 200 && status != 101) {
      data.final_chunk = false;
      return;
    }
    // This Mongoose version emits HTTP_MSG on CLOSE even for a truncated
    // Content-Length body. Do not mistake that event for successful delivery.
    auto* content_length = mg_http_get_header(message, "Content-Length");
    auto* transfer_encoding = mg_http_get_header(message, "Transfer-Encoding");
    std::uint64_t expected = 0;
    if (status < 200 || status > 599 ||
        (transfer_encoding && (mg_vcasecmp(transfer_encoding, "chunked") != 0 ||
                               !data.final_chunk || content_length)) ||
        (content_length && (!Decimal(content_length->ptr, content_length->len, expected) ||
                            expected != message->body.len))) {
      Finish(data, HttpRequestStatus::InvalidResponse, status);
    } else {
      Finish(data, status < 300 ? HttpRequestStatus::Success : HttpRequestStatus::HttpError, status);
    }
  } else if (event == MG_EV_ERROR) {
    Finish(data, HttpRequestStatus::ConnectionError);
  } else if (event == MG_EV_CLOSE) {
    data.closed = true;
  }
  if (data.done) connection->is_closing = 1;
}

bool HttpClient::SetConfig(std::string url, std::uint64_t timeout_ms) {
  std::string authority, uri;
  auto status = ParseUrl(url, authority, uri);
  if (status == HttpRequestStatus::Success && timeout_ms == 0)
    status = HttpRequestStatus::InvalidConfiguration;
  // Mongoose's URL parser requires '/' before a query-only request target.
  std::string connection_url;
  if (status == HttpRequestStatus::Success) connection_url = "http://" + authority + uri;
  std::lock_guard<std::mutex> lock(config_mutex_);
  config_status_ = status;
  if (status != HttpRequestStatus::Success) {
    url_.clear(); authority_.clear(); uri_.clear(); timeout_ms_ = 0;
    cancellation_epoch_.fetch_add(1);
    return false;
  }
  url_ = std::move(connection_url);
  authority_ = std::move(authority);
  uri_ = std::move(uri);
  timeout_ms_ = timeout_ms;
  return true;
}

void HttpClient::CancelPendingRequests() {
  std::lock_guard<std::mutex> lock(config_mutex_);
  if (config_status_ == HttpRequestStatus::Cancelled) return;
  config_status_ = HttpRequestStatus::Cancelled;
  cancellation_epoch_.fetch_add(1);
}

const char* HttpRequestStatusName(HttpRequestStatus status) {
  switch (status) {
    case HttpRequestStatus::Success: return "success";
    case HttpRequestStatus::NotConfigured: return "not_configured";
    case HttpRequestStatus::InvalidConfiguration: return "invalid_configuration";
    case HttpRequestStatus::UnsupportedScheme: return "unsupported_scheme";
    case HttpRequestStatus::ConnectFailed: return "connect_failed";
    case HttpRequestStatus::ConnectionError: return "connection_error";
    case HttpRequestStatus::ClosedWithoutResponse: return "closed_without_response";
    case HttpRequestStatus::InvalidResponse: return "invalid_response";
    case HttpRequestStatus::HttpError: return "http_error";
    case HttpRequestStatus::Timeout: return "timeout";
    case HttpRequestStatus::Cancelled: return "cancelled";
  }
  return "unknown";
}
}  // namespace wxhelper
