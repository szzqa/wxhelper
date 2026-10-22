#include "pch.h"
#include "hooks.h"
#include "thread_pool.h"
#include <array>
#include <atomic>
#include <chrono>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>

namespace {
void Check(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
struct FakeDetours {
  int begin = 0, update = 0, attach = 0, detach = 0, commit = 0, abort = 0;
  bool fail_begin = false, fail_update = false, fail_commit = false;
  int fail_attach = 0, fail_detach = 0;
  bool active = false;
  std::vector<std::pair<PVOID*, bool>> pending;
  std::set<PVOID*> installed;
  std::set<DWORD> enlisted;
} fake;
constexpr LONG kFailure = ERROR_ACCESS_DENIED;
std::atomic<int> native_messages{0}, native_sns{0}, delivered_http{0};
std::atomic<bool> configure_http_ok{true};
std::atomic<bool> block_native{false}, reenter_native{false};
std::atomic<bool> cross_thread_reentry{false};
HANDLE native_entered = nullptr, native_release = nullptr;
UINT64 NativeMessage(UINT64 a, UINT64, UINT64 c) {
  ++native_messages;
  if (block_native.exchange(false)) {
    SetEvent(native_entered);
    WaitForSingleObject(native_release, 5000);
    if (reenter_native.exchange(false)) {
      // The transition may already be waiting for this outer callback.
      std::array<unsigned char, 128> data{};
      const auto nested = [&] {
        wxhelper::hooks::testing::InvokeSns(0, reinterpret_cast<UINT64>(data.data()), 0);
      };
      if (cross_thread_reentry) { std::thread other(nested); other.join(); }
      else nested();
    }
  }
  return a + c + 100;
}
UINT64 NativeSns(UINT64 a, UINT64, UINT64 c) { ++native_sns; return a + c + 200; }
UINT64 NativeLog(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64,
                 UINT64, UINT64, UINT64, UINT64, UINT64, UINT64) { return 0; }
void Reset() {
  wxhelper::ThreadPool::GetInstance().Stop();
  fake = {};
  wxhelper::hooks::testing::Reset(NativeMessage, NativeSns, NativeLog);
  configure_http_ok = true;
}
int Install() { return wxhelper::hooks::HookSyncMsg("127.0.0.1", 19099, "http://fixture/", 100, true); }

void Transactions() {
  using namespace wxhelper::hooks;
  Reset();
  configure_http_ok = false;
  Check(Install() == ERROR_INVALID_PARAMETER && !fake.begin, "reject invalid HTTP config before attach");
  configure_http_ok = true;
  fake.fail_begin = true;
  Check(Install() == kFailure && !testing::MessagesInstalled() && fake.installed.empty(), "begin failure");
  fake.fail_begin = false;
  fake.fail_attach = 2;
  Check(Install() == kFailure && fake.abort == 1 && fake.installed.empty() && !testing::MessagesInstalled(),
        "second attach aborts whole message/SNS pair");
  fake.fail_attach = 0;
  fake.fail_update = true;
  Check(Install() == kFailure && fake.pending.empty() && fake.installed.empty(), "update failure aborts staged pair");
  fake.fail_update = false;
  fake.fail_commit = true;
  Check(Install() == kFailure && fake.installed.empty() && !testing::MessagesInstalled(), "commit failure rolls back flags");
  fake.fail_commit = false;
  Check(Install() == NO_ERROR && fake.installed.size() == 2 && testing::MessagesInstalled(), "pair installed together");
  const int commits = fake.commit;
  Check(Install() == 2 && fake.commit == commits, "duplicate install has no transaction");
  fake.fail_detach = fake.detach + 2;
  Check(UnHookSyncMsg() == kFailure && fake.installed.size() == 2 && testing::MessagesInstalled(),
        "second detach aborts whole pair and preserves retry state");
  fake.fail_detach = 0;
  Check(UnHookSyncMsg() == NO_ERROR && fake.installed.empty() && !testing::MessagesInstalled(), "retry removes both hooks");
  Check(UnHookSyncMsg() == NO_ERROR, "unhook idempotence");
  Check(Install() == NO_ERROR && HookLog() == NO_ERROR && fake.installed.size() == 3, "all installed");
  fake.fail_commit = true;
  Check(StopAll() == kFailure && testing::MessagesInstalled() && testing::LogInstalled() && fake.installed.size() == 3,
        "StopAll failure preserves all installed state");
  Check(Install() == ERROR_OPERATION_ABORTED && HookLog() == ERROR_OPERATION_ABORTED,
        "stop permanently rejects registrations even after failure");
  // No valid message structure is supplied: stopping callbacks must only forward.
  Check(testing::InvokeMessage(3, 0, 4) == 107 && testing::InvokeSns(2, 0, 5) == 207,
        "stopping hooks forward native result without capture");
  fake.fail_commit = false;
  Check(StopAll() == NO_ERROR && fake.installed.empty() && !testing::MessagesInstalled() && !testing::LogInstalled(),
        "StopAll retry removes all hooks");
  Check(StopAll() == NO_ERROR, "StopAll idempotence");
}

void CallbacksAndOwnership() {
  using namespace wxhelper::hooks;
  Reset();
  Check(Install() == NO_ERROR, "ownership fixture installed");
  Check(!testing::QueuePayload("{\"fixture\":1}\n") && testing::PendingDeliveries() == 0,
        "AddWork failure frees delivery");
  auto& pool = wxhelper::ThreadPool::GetInstance();
  Check(pool.Create(1, 2), "fixture pool");
  std::array<unsigned char, 128> data{};
  Check(testing::InvokeMessage(7, reinterpret_cast<UINT64>(data.data()), 8) == 115,
        "message hook preserves native UINT64 return");
  Check(testing::InvokeSns(4, reinterpret_cast<UINT64>(data.data()), 5) == 209,
        "SNS hook preserves native UINT64 return");
  Check(pool.Stop() && testing::PendingDeliveries() == 0 && delivered_http >= 2,
        "accepted deliveries released after callbacks");

  for (bool other_thread : {false, true}) {
    Reset(); Check(Install() == NO_ERROR, "drain fixture installed");
    ResetEvent(native_entered); ResetEvent(native_release);
    block_native = true; reenter_native = true; cross_thread_reentry = other_thread;
    std::thread callback([&] { testing::InvokeMessage(0, reinterpret_cast<UINT64>(data.data()), 0); });
    const bool entered = WaitForSingleObject(native_entered, 2000) == WAIT_OBJECT_0;
    std::atomic<bool> stop_finished{false};
    int stop_result = -1;
    std::thread stopping([&] { stop_result = StopAll(); stop_finished = true; });
    // Wait for the transition to really start before releasing the original.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    bool drain_started = false;
    while (!(drain_started = testing::Stopping()) && std::chrono::steady_clock::now() < deadline)
      std::this_thread::yield();
    const bool waited = !stop_finished.load();
    SetEvent(native_release);
    callback.join(); stopping.join();
    Check(entered && drain_started && waited && stop_result == NO_ERROR,
          "detach drains native calls including cross-thread synchronous reentry");
    Check(fake.enlisted.count(GetCurrentThreadId()) == 1,
          "transaction enlists other live host threads, not just its own pseudo handle");
  }
}

struct Listener {
  SOCKET value = INVALID_SOCKET;
  int port = 0;
  Listener() {
    value = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Check(value != INVALID_SOCKET, "fixture socket");
    sockaddr_in address{}; address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Check(bind(value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 && listen(value, 1) == 0,
          "fixture listen");
    int length = sizeof(address);
    Check(getsockname(value, reinterpret_cast<sockaddr*>(&address), &length) == 0, "fixture port");
    port = ntohs(address.sin_port);
  }
  ~Listener() { if (value != INVALID_SOCKET) closesocket(value); }
};
void Tcp() {
  using namespace wxhelper::hooks;
  WSADATA data{};
  Check(WSAStartup(MAKEWORD(2, 2), &data) == 0, "fixture WSAStartup");
  {
    Listener listener;
    const std::string payload(2 * 1024 * 1024 + 33, 'x');
    std::string received;
    std::thread server([&] {
      SOCKET client = accept(listener.value, nullptr, nullptr);
      if (client == INVALID_SOCKET) return;
      DWORD timeout = 3000;
      setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
      char buffer[4096];
      for (;;) { int count = recv(client, buffer, sizeof(buffer), 0); if (count <= 0) break; received.append(buffer, count); }
      send(client, "ok", 2, 0); closesocket(client);
    });
    const bool sent = testing::SendTcpPayload("127.0.0.1", listener.port, 5000, payload);
    server.join();
    Check(sent && received == payload, "TCP full payload across multiple sends");
    Check(testing::WinsockReferences() == 0, "success balances owned Winsock references");
  }
  {
    Listener listener;
    HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::thread server([&] {
      SOCKET client = accept(listener.value, nullptr, nullptr);
      if (client != INVALID_SOCKET) { WaitForSingleObject(release, 3000); closesocket(client); }
    });
    const auto start = std::chrono::steady_clock::now();
    const bool sent = testing::SendTcpPayload("127.0.0.1", listener.port, 100, "fixture");
    const auto elapsed = std::chrono::steady_clock::now() - start;
    SetEvent(release); server.join(); CloseHandle(release);
    Check(!sent && elapsed < std::chrono::seconds(2), "TCP silent peer is bounded by total timeout");
    Check(testing::WinsockReferences() == 0, "timeout balances owned Winsock references");
  }
  Check(!testing::SendTcpPayload("not-an-ip", 1, 100, "fixture"), "invalid address cleanup");
  Check(testing::WinsockReferences() == 0, "invalid address balances owned Winsock references");
  {
    Reset();
    Listener listener;
    HANDLE accepted = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Check(accepted && release, "TCP cancellation fixture events");
    auto& pool = wxhelper::ThreadPool::GetInstance();
    Check(HookSyncMsg("127.0.0.1", listener.port, "", 60000, false) == NO_ERROR && pool.Create(1, 1),
          "TCP cancellation fixture install");
    std::thread server([&] {
      SOCKET client = accept(listener.value, nullptr, nullptr);
      if (client != INVALID_SOCKET) {
        SetEvent(accepted); WaitForSingleObject(release, 3000); closesocket(client);
      }
    });
    const bool queued_first = testing::QueuePayload("active fixture");
    const bool active = WaitForSingleObject(accepted, 2000) == WAIT_OBJECT_0;
    bool queued_rest = true;
    for (int i = 0; i != 8; ++i) queued_rest = testing::QueuePayload("queued fixture") && queued_rest;
    const auto start = std::chrono::steady_clock::now();
    const auto stop_result = StopAll();
    const bool drained = pool.Stop();
    const auto elapsed = std::chrono::steady_clock::now() - start;
    SetEvent(release); server.join(); CloseHandle(accepted); CloseHandle(release);
    Check(queued_first && queued_rest && active && stop_result == NO_ERROR && drained &&
              testing::PendingDeliveries() == 0 && elapsed < std::chrono::seconds(1),
          "Stop cancels active TCP and frees queued contexts without per-item timeouts");
    Check(testing::WinsockReferences() == 0, "cancellation balances owned Winsock references");
  }
  // Other socket providers can hold their own process-wide Winsock lifetime.
  // Check our real startup/cleanup pairs above, rather than assuming the whole
  // process must become uninitialized after a loopback connection.
  Check(WSACleanup() == 0, "fixture Winsock cleanup");
}
}  // namespace

extern "C" LONG WINAPI DetourTransactionBegin() {
  ++fake.begin;
  if (fake.fail_begin) return kFailure;
  fake.active = true; fake.pending.clear(); fake.enlisted.clear(); return NO_ERROR;
}
extern "C" LONG WINAPI DetourUpdateThread(HANDLE thread) {
  fake.enlisted.insert(GetThreadId(thread));
  ++fake.update; return fake.fail_update ? kFailure : NO_ERROR;
}
extern "C" LONG WINAPI DetourAttach(PVOID* pointer, PVOID) {
  ++fake.attach;
  if (fake.attach == fake.fail_attach) return kFailure;
  fake.pending.push_back({pointer, true}); return NO_ERROR;
}
extern "C" LONG WINAPI DetourDetach(PVOID* pointer, PVOID) {
  ++fake.detach;
  if (fake.detach == fake.fail_detach) return kFailure;
  fake.pending.push_back({pointer, false}); return NO_ERROR;
}
extern "C" LONG WINAPI DetourTransactionAbort() {
  ++fake.abort; fake.pending.clear(); fake.active = false; return NO_ERROR;
}
extern "C" LONG WINAPI DetourTransactionCommit() {
  ++fake.commit;
  if (fake.fail_commit) { DetourTransactionAbort(); return kFailure; }
  for (const auto& operation : fake.pending) {
    if (operation.second) fake.installed.insert(operation.first);
    else fake.installed.erase(operation.first);
  }
  fake.pending.clear(); fake.active = false; return NO_ERROR;
}
namespace wxhelper {
std::string Utils::ReadSKBuiltinString(INT64) { return "fixture"; }
std::string Utils::ReadSKBuiltinBuffer(INT64) { return {}; }
std::string Utils::ReadWeChatStr(INT64) { return "fixture"; }
std::string Utils::ReadWstringThenConvert(INT64) { return "fixture"; }
std::wstring Utils::UTF8ToWstring(const std::string&) { return L"fixture"; }
std::string Utils::WstringToAnsi(const std::wstring&, INT64) { return "fixture"; }
namespace hooks::testing {
bool ConfigureHttp(const std::string&, std::uint64_t) { return configure_http_ok.load(); }
void SendHttp(const std::string&) { ++delivered_http; }
}
}
int main() {
  native_entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  native_release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  try {
    Check(native_entered && native_release, "fixture native events");
    Transactions(); CallbacksAndOwnership(); Tcp();
    CloseHandle(native_entered); CloseHandle(native_release);
    std::cout << "PASS: fake hook transactions, callback quiescence, native forwarding, delivery ownership and TCP deadlines\n";
    return 0;
  } catch (const std::exception& error) {
    SetEvent(native_release);
    wxhelper::ThreadPool::GetInstance().Stop();
    CloseHandle(native_entered); CloseHandle(native_release);
    std::cerr << error.what() << '\n';
    return 1;
  }
}
