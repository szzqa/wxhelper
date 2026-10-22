#include <WinSock2.h>
#include <Windows.h>

#include "http_client.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <future>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using wxhelper::HttpClient;
using wxhelper::HttpRequestResult;
using wxhelper::HttpRequestStatus;
using namespace std::chrono_literals;

namespace {
SOCKET BindLoopback(unsigned short& port) {
  const SOCKET socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  assert(socket_handle != INVALID_SOCKET);
  BOOL exclusive = TRUE;
  assert(setsockopt(socket_handle, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) == 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  assert(bind(socket_handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
  int size = sizeof(address);
  assert(getsockname(socket_handle, reinterpret_cast<sockaddr*>(&address), &size) == 0);
  port = ntohs(address.sin_port);
  return socket_handle;
}

bool Readable(SOCKET socket_handle) {
  fd_set reads;
  FD_ZERO(&reads);
  FD_SET(socket_handle, &reads);
  timeval wait{0, 20000};
  return select(0, &reads, nullptr, nullptr, &wait) > 0;
}

enum class Behavior {
  Reply, Disconnect, Silent, GatedReply, Truncated, HttpError,
  CloseDelimited, Chunked, TruncatedChunked, InterimTruncatedChunked
};

// Fake HTTP server. Every socket binds/connects only to 127.0.0.1. All loops
// have a stop flag/deadline so a failed client does not strand the test process.
class LoopbackServer {
 public:
  explicit LoopbackServer(Behavior behavior) : behavior_(behavior) {
    listener_ = BindLoopback(port_);
    assert(listen(listener_, 32) == 0);
    worker_ = std::thread([this] { Serve(); });
  }
  ~LoopbackServer() {
    stop_.store(true);
    release_.store(true);
    worker_.join();
    closesocket(listener_);
  }
  std::string Url(const std::string& target = "/callback") const {
    return "http://127.0.0.1:" + std::to_string(port_) + target;
  }
  bool WaitForRequest() {
    std::unique_lock<std::mutex> lock(mutex_);
    return changed_.wait_for(lock, 3s, [this] { return !requests_.empty(); });
  }
  void Release() { release_.store(true); }
  std::vector<std::string> Requests() {
    std::lock_guard<std::mutex> lock(mutex_);
    return requests_;
  }

 private:
  void Serve() {
    while (!stop_.load()) {
      if (!Readable(listener_)) continue;
      SOCKET peer = accept(listener_, nullptr, nullptr);
      if (peer == INVALID_SOCKET) continue;
      DWORD timeout = 500;
      setsockopt(peer, SOL_SOCKET, SO_SNDTIMEO,
                 reinterpret_cast<const char*>(&timeout), sizeof(timeout));
      std::string request;
      const auto deadline = std::chrono::steady_clock::now() + 3s;
      bool complete = false;
      while (!stop_.load() && std::chrono::steady_clock::now() < deadline) {
        if (!Readable(peer)) continue;
        char bytes[4096];
        const int count = recv(peer, bytes, sizeof(bytes), 0);
        if (count <= 0) break;
        request.append(bytes, static_cast<std::size_t>(count));
        const auto headers = request.find("\r\n\r\n");
        const auto length = request.find("Content-Length: ");
        if (headers == std::string::npos || length == std::string::npos) continue;
        const auto body_length = std::stoull(request.substr(length + 16));
        if (request.size() >= headers + 4 + body_length) { complete = true; break; }
      }
      if (complete) {
        {
          std::lock_guard<std::mutex> lock(mutex_);
          requests_.push_back(request);
        }
        changed_.notify_all();
        if (behavior_ == Behavior::Silent) {
          while (!stop_.load() && std::chrono::steady_clock::now() < deadline) {
            if (Readable(peer)) {
              char extra[64];
              if (recv(peer, extra, sizeof(extra), 0) <= 0) break;
            }
          }
        } else if (behavior_ != Behavior::Disconnect) {
          while (behavior_ == Behavior::GatedReply && !release_.load() &&
                 !stop_.load() && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(1ms);
          std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
          if (behavior_ == Behavior::Truncated)
            response = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nx";
          else if (behavior_ == Behavior::HttpError)
            response = "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n";
          else if (behavior_ == Behavior::CloseDelimited)
            response = "HTTP/1.0 200 OK\r\n\r\nok";
          else if (behavior_ == Behavior::Chunked || behavior_ == Behavior::TruncatedChunked ||
                   behavior_ == Behavior::InterimTruncatedChunked) {
            response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n";
            if (behavior_ == Behavior::Chunked) response += "0\r\n\r\n";
            if (behavior_ == Behavior::InterimTruncatedChunked)
              response.insert(0, "HTTP/1.1 100 Continue\r\n\r\n");
          }
          if (!stop_.load()) send(peer, response.data(), static_cast<int>(response.size()), 0);
        }
      }
      shutdown(peer, SD_BOTH);
      closesocket(peer);
    }
  }
  Behavior behavior_;
  SOCKET listener_ = INVALID_SOCKET;
  unsigned short port_ = 0;
  std::atomic<bool> stop_{false}, release_{false};
  std::thread worker_;
  std::mutex mutex_;
  std::condition_variable changed_;
  std::vector<std::string> requests_;
};

HttpRequestResult Bounded(std::future<HttpRequestResult>& request) {
  assert(request.wait_for(4s) == std::future_status::ready);
  return request.get();
}
}  // namespace

int main() {
  _set_error_mode(_OUT_TO_STDERR);
  _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
  WSADATA winsock{};
  assert(WSAStartup(MAKEWORD(2, 2), &winsock) == 0);
  mg_log_set(MG_LL_NONE);
  HttpClient client;
  assert(client.SendRequest("{}").status == HttpRequestStatus::NotConfigured);
  assert(!client.SetConfig("https://127.0.0.1:1/callback", 100));
  assert(client.SendRequest("{}").status == HttpRequestStatus::UnsupportedScheme);
  for (const auto* url : {"http://", "http://127.0.0.1:0/", "http://127.0.0.1:65536/",
                          "http://127.0.0.1:999999999999999999999/", "http://127.0.0.1:/",
                          "http://user@127.0.0.1/", "http://127.0.0.1/\r\nX: y"}) {
    assert(!client.SetConfig(url, 100));
    assert(client.SendRequest("{}").status == HttpRequestStatus::InvalidConfiguration);
  }
  assert(!client.SetConfig("http://127.0.0.1/", 0));

  {
    LoopbackServer server(Behavior::Reply);
    assert(client.SetConfig(server.Url("?test=1"), 1500));
    const std::string content = std::string("{\"value\":\"") + std::string(8192, 'x') + "\"}";
    auto request = std::async(std::launch::async, [&] { return client.SendRequest(content); });
    const auto result = Bounded(request);
    assert(result.status == HttpRequestStatus::Success && result.http_status == 200);
    const auto received = server.Requests();
    assert(received.size() == 1 && received[0].find("POST /?test=1 HTTP/1.1\r\n") == 0);
    assert(received[0].substr(received[0].find("\r\n\r\n") + 4) == content);
    assert(received[0].find("Host: " + server.Url().substr(7, server.Url().find('/', 7) - 7) + "\r\n") != std::string::npos);
  }
  {
    unsigned short port = 0;
    const SOCKET reserved = BindLoopback(port);  // Bound, deliberately not listening.
    assert(client.SetConfig("http://127.0.0.1:" + std::to_string(port) + "/", 3000));
    auto request = std::async(std::launch::async, [&] { return client.SendRequest("{}"); });
    const auto result = Bounded(request);
    if (result.status != HttpRequestStatus::ConnectionError)
      std::cerr << "Refused connection result: " << wxhelper::HttpRequestStatusName(result.status) << '\n';
    assert(result.status == HttpRequestStatus::ConnectionError);
    closesocket(reserved);
  }
  for (const auto behavior : {Behavior::Disconnect, Behavior::Truncated, Behavior::HttpError}) {
    LoopbackServer server(behavior);
    assert(client.SetConfig(server.Url(), 1500));
    auto request = std::async(std::launch::async, [&] { return client.SendRequest("{}"); });
    const auto result = Bounded(request);
    const auto expected = behavior == Behavior::Disconnect ? HttpRequestStatus::ClosedWithoutResponse
        : behavior == Behavior::Truncated ? HttpRequestStatus::InvalidResponse : HttpRequestStatus::HttpError;
    assert(result.status == expected);
    if (behavior == Behavior::HttpError) assert(result.http_status == 503);
  }
  for (const auto behavior : {Behavior::CloseDelimited, Behavior::Chunked,
                              Behavior::TruncatedChunked, Behavior::InterimTruncatedChunked}) {
    LoopbackServer server(behavior);
    assert(client.SetConfig(server.Url(), 1500));
    auto request = std::async(std::launch::async, [&] { return client.SendRequest(""); });
    const auto expected = behavior == Behavior::TruncatedChunked
        ? HttpRequestStatus::InvalidResponse : HttpRequestStatus::Success;
    const auto result = Bounded(request);
    if (behavior == Behavior::InterimTruncatedChunked) {
      // This bundled parser can consume the trailing bytes with the interim
      // message on CLOSE. Neither form of incomplete response may succeed.
      assert(result.status == HttpRequestStatus::ClosedWithoutResponse ||
             result.status == HttpRequestStatus::InvalidResponse);
    } else {
      assert(result.status == expected);
    }
  }
  {
    LoopbackServer server(Behavior::Silent);
    assert(client.SetConfig(server.Url(), 200));
    const auto started = std::chrono::steady_clock::now();
    auto request = std::async(std::launch::async, [&] { return client.SendRequest("{}"); });
    assert(server.WaitForRequest());
    assert(Bounded(request).status == HttpRequestStatus::Timeout);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    assert(elapsed >= 180ms && elapsed < 1500ms);
  }
  {
    LoopbackServer old_server(Behavior::GatedReply), new_server(Behavior::Reply);
    assert(client.SetConfig(old_server.Url("/old"), 1500));
    auto old_request = std::async(std::launch::async, [&] { return client.SendRequest("old"); });
    assert(old_server.WaitForRequest());
    assert(client.SetConfig(new_server.Url("/new"), 1000));
    assert(client.SendRequest("new").status == HttpRequestStatus::Success);
    old_server.Release();
    assert(Bounded(old_request).status == HttpRequestStatus::Success);
    assert(old_server.Requests()[0].find("POST /old ") == 0);
    assert(new_server.Requests()[0].find("POST /new ") == 0);
  }
  {
    LoopbackServer first(Behavior::Silent), second(Behavior::Silent);
    assert(client.SetConfig(first.Url(), 3000));
    auto one = std::async(std::launch::async, [&] { return client.SendRequest("one"); });
    assert(first.WaitForRequest());
    assert(client.SetConfig(second.Url(), 3000));
    auto two = std::async(std::launch::async, [&] { return client.SendRequest("two"); });
    assert(second.WaitForRequest());
    const auto cancelled = std::chrono::steady_clock::now();
    client.CancelPendingRequests(); client.CancelPendingRequests();
    assert(Bounded(one).status == HttpRequestStatus::Cancelled);
    assert(Bounded(two).status == HttpRequestStatus::Cancelled);
    assert(std::chrono::steady_clock::now() - cancelled < 1000ms);
    assert(client.SendRequest("queued").status == HttpRequestStatus::Cancelled);
  }
  // Race configuration snapshots against simultaneous request starts. Each
  // server must see its own target, never a URL from a different generation.
  {
    LoopbackServer alpha(Behavior::Reply), beta(Behavior::Reply);
    assert(client.SetConfig(alpha.Url("/alpha"), 2000));
    std::atomic<bool> done{false};
    std::thread configure([&] {
      while (!done.load()) {
        assert(client.SetConfig(alpha.Url("/alpha"), 2000));
        assert(client.SetConfig(beta.Url("/beta"), 2000));
        std::this_thread::yield();
      }
    });
    std::vector<std::future<HttpRequestResult>> requests;
    for (int i = 0; i < 12; ++i)
      requests.push_back(std::async(std::launch::async, [&] { return client.SendRequest("race"); }));
    for (auto& request : requests) assert(Bounded(request).status == HttpRequestStatus::Success);
    done.store(true); configure.join();
    const auto a = alpha.Requests(), b = beta.Requests();
    assert(a.size() + b.size() == 12);
    for (const auto& request : a) assert(request.find("POST /alpha ") == 0);
    for (const auto& request : b) assert(request.find("POST /beta ") == 0);
  }
  // Starts racing a stop may snapshot before or after it; neither path may
  // escape cancellation or leave a queued callback able to send afterwards.
  for (int round = 0; round < 8; ++round) {
    LoopbackServer server(Behavior::Silent);
    assert(client.SetConfig(server.Url(), 3000));
    std::atomic<bool> go{false};
    auto request = std::async(std::launch::async, [&] {
      while (!go.load()) std::this_thread::yield();
      return client.SendRequest("stop-race");
    });
    go.store(true);
    client.CancelPendingRequests();
    assert(Bounded(request).status == HttpRequestStatus::Cancelled);
    assert(client.SendRequest("after-stop").status == HttpRequestStatus::Cancelled);
  }
  {
    LoopbackServer server(Behavior::Silent);
    assert(client.SetConfig(server.Url(), 3000));
    auto request = std::async(std::launch::async, [&] { return client.SendRequest("invalid-config"); });
    assert(server.WaitForRequest());
    assert(!client.SetConfig("https://127.0.0.1/", 100));
    assert(Bounded(request).status == HttpRequestStatus::Cancelled);
    assert(client.SendRequest("after-invalid").status == HttpRequestStatus::UnsupportedScheme);
  }
  client.CancelPendingRequests();
  WSACleanup();
  std::cout << "HTTP client loopback success, refusal, disconnect, timeout, configuration races and cancellation: PASS\n";
}
