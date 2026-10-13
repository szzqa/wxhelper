#include <WinSock2.h>
#include <Windows.h>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>
#include "http_server_callback.h"
template <typename... Args> static void TestLog(Args&&...) {}
#define SPDLOG_ERROR(...) TestLog(__VA_ARGS__)
static bool fail_next_thread = false;
static HANDLE WINAPI TestCreateThread(LPSECURITY_ATTRIBUTES attributes,
    SIZE_T stack_size, LPTHREAD_START_ROUTINE start, LPVOID context,
    DWORD flags, LPDWORD thread_id) {
  if (fail_next_thread) {
    fail_next_thread = false;
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return nullptr;
  }
  return ::CreateThread(attributes, stack_size, start, context, flags, thread_id);
}
#define CreateThread TestCreateThread
// Generated directly from src/http_server.cc and StartHttpServer in the callback
// source by run_http_lifecycle_test.ps1. No WeChat code is loaded or executed.
#include "http_server_under_test.cc"
#include "http_worker_under_test.inc"
#undef CreateThread
void EventHandler(mg_connection *c, int ev, void *, void *) {
  if (ev == MG_EV_HTTP_MSG) mg_http_reply(c, 200, "", "lifecycle-ok");
}
static SOCKET BindPort(int requested, int *actual = nullptr) {
  SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  assert(fd != INVALID_SOCKET);
  BOOL exclusive = TRUE;
  assert(setsockopt(fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   reinterpret_cast<const char *>(&exclusive), sizeof(exclusive)) == 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(static_cast<u_short>(requested));
  assert(bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
  int len = sizeof(addr);
  assert(getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
  if (actual) *actual = ntohs(addr.sin_port);
  return fd;
}
static int FreePort() {
  int port = 0;
  SOCKET fd = BindPort(0, &port);
  closesocket(fd);
  return port;
}
static void Request(int port) {
  SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  assert(fd != INVALID_SOCKET);
  DWORD timeout = 2000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
             reinterpret_cast<const char *>(&timeout), sizeof(timeout));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(static_cast<u_short>(port));
  assert(connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
  const char request[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
  assert(send(fd, request, sizeof(request)-1, 0) > 0);
  char response[1024]{};
  const int n = recv(fd, response, sizeof(response)-1, 0);
  assert(n > 0);
  assert(std::string(response, n).find("200 OK") != std::string::npos);
  closesocket(fd);
}
int main() {
  WSADATA data{};
  assert(WSAStartup(MAKEWORD(2, 2), &data) == 0);
  mg_log_set(MG_LL_NONE);
  for (int invalid : {-1, 0, 65536}) {
    wxhelper::HttpServer server(invalid);
    assert(!server.HttpStart());
    assert(!server.GetRunning());
    assert(server.HttpClose());
  }
  int occupied_port = 0;
  SOCKET occupied = BindPort(0, &occupied_port);
  assert(listen(occupied, 1) == 0);
  {
    wxhelper::HttpServer server(occupied_port);
    assert(!server.HttpStart());
    assert(!server.GetRunning());
    closesocket(occupied);
    assert(server.HttpStart());
    assert(server.HttpStart());
    Request(occupied_port);
    assert(server.HttpClose());
    assert(!server.GetRunning());
    assert(server.HttpClose());
    SOCKET available = BindPort(occupied_port);
    closesocket(available);
    for (int i = 0; i < 10; ++i) {
      assert(server.HttpStart());
      Request(occupied_port);
      const auto start = std::chrono::steady_clock::now();
      assert(server.HttpClose());
      assert(std::chrono::steady_clock::now() - start < std::chrono::seconds(2));
    }
  }
  {
    const int port = FreePort();
    wxhelper::HttpServer server(port);
    fail_next_thread = true;
    assert(!server.HttpStart());
    assert(!server.GetRunning());
    SOCKET available = BindPort(port);
    closesocket(available);
    assert(server.HttpStart());
    Request(port);
    assert(server.HttpClose());
  }
  const int destructor_port = FreePort();
  {
    wxhelper::HttpServer server(destructor_port);
    assert(server.HttpStart());
    Request(destructor_port);
  }
  SOCKET available = BindPort(destructor_port);
  closesocket(available);
  {
    wxhelper::HttpServer server(FreePort());
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) {
      threads.emplace_back([&] {
        for (int j = 0; j < 5; ++j) {
          assert(server.HttpStart());
          assert(server.HttpClose());
        }
      });
    }
    for (auto &thread : threads) thread.join();
    assert(!server.GetRunning());
  }
  std::puts("PASS: invalid port, occupied port, HTTP request, repeated start/stop, thread creation failure, active destructor, concurrent lifecycle");
}
