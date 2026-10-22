#include "pch.h"
#include "hooks.h"
#include "thread_pool.h"
#include <WS2tcpip.h>
#include <tlhelp32.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include "base64.h"
#ifndef WXHELPER_HOOK_TESTING
#include "http_client.h"
#endif

namespace offset = wxhelper::V3_9_5_81::offset;
namespace wxhelper::hooks {
namespace {
using MessageFunction = UINT64 (*)(UINT64, UINT64, UINT64);
using LogFunction = UINT64 (*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64,
                              UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);
MessageFunction original_message = nullptr;
MessageFunction original_sns = nullptr;
LogFunction original_log = nullptr;

struct DeliveryConfig {
  bool http = false;
  std::string ip;
  int port = 0;
  std::uint64_t timeout_ms = 5000;
  const std::atomic<bool>* cancelled = nullptr;
};
struct HookState {
  std::mutex operation;
  std::mutex mutex;
  std::condition_variable changed;
  bool transitioning = false;
  std::atomic<bool> stopping{false};
  bool messages = false;  // Message and SNS are always one transaction.
  bool log = false;
  std::size_t callbacks = 0;
  std::atomic<std::size_t> deliveries{0};
  std::shared_ptr<const DeliveryConfig> config;
};
HookState& State() { static auto* state = new HookState(); return *state; }
thread_local unsigned callback_depth = 0;

class CallbackGuard {
 public:
  CallbackGuard() {
    auto& state = State();
    std::unique_lock<std::mutex> lock(state.mutex);
    // Keep forwarding during drain: an active native call may synchronously
    // wait for a hook on another thread. Blocking that entry would deadlock.
    // After the count reaches zero, Transition keeps this mutex locked until
    // commit/abort, so no callback can acquire a changing trampoline.
    ++callback_depth;
    ++state.callbacks;
    messages = state.messages && !state.stopping && !state.transitioning;
    log = state.log && !state.stopping && !state.transitioning;
    config = state.config;
  }
  ~CallbackGuard() {
    auto& state = State();
    std::lock_guard<std::mutex> lock(state.mutex);
    --callback_depth;
    if (--state.callbacks == 0) state.changed.notify_all();
  }
  bool messages = false;
  bool log = false;
  std::shared_ptr<const DeliveryConfig> config;
};

// Keep callbacks out of the trampoline-change window. Existing callbacks,
// including their original native call, finish before a detach is attempted.
class Transition {
 public:
  explicit Transition(bool stop_all = false)
      : operation_(State().operation), lock_(State().mutex) {
    auto& state = State();
    if (stop_all) state.stopping = true;
    state.transitioning = true;
    state.changed.wait(lock_, [&] { return state.callbacks == 0; });
  }
  ~Transition() {
    State().transitioning = false;
    lock_.unlock();
    State().changed.notify_all();
  }
 private:
  std::unique_lock<std::mutex> operation_;
  std::unique_lock<std::mutex> lock_;
};

struct ThreadHandles {
  std::vector<HANDLE> values;
  ~ThreadHandles() { for (auto handle : values) CloseHandle(handle); }
  LONG Capture() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return GetLastError();
    THREADENTRY32 item{};
    item.dwSize = sizeof(item);
    LONG result = NO_ERROR;
    BOOL found = Thread32First(snapshot, &item);
    if (!found && GetLastError() != ERROR_NO_MORE_FILES) result = GetLastError();
    while (found) {
      if (item.th32OwnerProcessID == GetCurrentProcessId() &&
          item.th32ThreadID != GetCurrentThreadId()) {
        HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                       THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                   FALSE, item.th32ThreadID);
        if (!thread) {
          const auto error = GetLastError();
          if (error != ERROR_INVALID_PARAMETER) { result = error; break; }
        } else if (GetProcessIdOfThread(thread) != GetCurrentProcessId()) {
          CloseHandle(thread);
        } else {
          try { values.push_back(thread); }
          catch (...) { CloseHandle(thread); result = ERROR_NOT_ENOUGH_MEMORY; break; }
        }
      }
      found = Thread32Next(snapshot, &item);
      if (!found && GetLastError() != ERROR_NO_MORE_FILES) result = GetLastError();
    }
    CloseHandle(snapshot);
    return result;
  }
};

struct Change { PVOID* target; PVOID callback; bool attach; };
LONG ApplyChanges(std::initializer_list<Change> changes) {
  ThreadHandles threads;
  LONG result = DetourTransactionBegin();
  if (result != NO_ERROR) return result;
  // Stage allocations before suspending other threads. Every error aborts the
  // complete transaction, so a message/SNS pair can never be half published.
  for (const auto& change : changes) {
    result = change.attach ? DetourAttach(change.target, change.callback)
                           : DetourDetach(change.target, change.callback);
    if (result != NO_ERROR) { DetourTransactionAbort(); return result; }
  }
  // Snapshot as late as possible, after staging and before suspending any
  // thread. Handles stay valid until commit/abort has resumed the threads.
  result = threads.Capture();
  if (result != NO_ERROR) { DetourTransactionAbort(); return result; }
  result = DetourUpdateThread(GetCurrentThread());
  if (result == NO_ERROR) {
    for (auto thread : threads.values) {
      result = DetourUpdateThread(thread);
      if (result != NO_ERROR) break;
    }
  }
  if (result != NO_ERROR) { DetourTransactionAbort(); return result; }
  // Detours aborts its own pending transaction on commit failure. State flags
  // below are updated only on success; the caller may retry a failed detach.
  return DetourTransactionCommit();
}

#ifdef WXHELPER_HOOK_TESTING
std::atomic<long> owned_winsock_references{0};
#endif
class Winsock {
 public:
  Winsock() {
    WSADATA data{};
    ok = WSAStartup(MAKEWORD(2, 2), &data) == 0;
#ifdef WXHELPER_HOOK_TESTING
    if (ok) ++owned_winsock_references;
#endif
  }
  ~Winsock() {
    if (!ok) return;
    const auto result = WSACleanup();
#ifdef WXHELPER_HOOK_TESTING
    if (result == 0) --owned_winsock_references;
#endif
    if (result != 0) OutputDebugStringA("wxhelper: WSACleanup failed.");
  }
  bool ok = false;
};
class Socket {
 public:
  Socket() : value(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) {}
  ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
  SOCKET value;
};
using Clock = std::chrono::steady_clock;
bool Cancelled(const DeliveryConfig& config) {
  return config.cancelled && config.cancelled->load();
}
bool WaitSocket(SOCKET socket, bool writing, Clock::time_point deadline,
                const DeliveryConfig& config) {
  while (Clock::now() < deadline) {
    if (Cancelled(config)) return false;
    const auto left = std::chrono::duration_cast<std::chrono::microseconds>(deadline - Clock::now()).count();
    if (left <= 0) return false;
    // A single deadline covers the complete exchange; short select slices
    // additionally let StopAll cancel an in-flight TCP delivery promptly.
    const auto slice = (std::min)(left, decltype(left){25000});
    timeval timeout{static_cast<long>(slice / 1000000), static_cast<long>(slice % 1000000)};
    fd_set ready, errors;
    FD_ZERO(&ready); FD_ZERO(&errors);
    FD_SET(socket, &ready); FD_SET(socket, &errors);
    const int result = select(0, writing ? nullptr : &ready,
                              writing ? &ready : nullptr, &errors, &timeout);
    if (result > 0) return !Cancelled(config) && !FD_ISSET(socket, &errors) && FD_ISSET(socket, &ready);
    if (result < 0 && WSAGetLastError() != WSAEINTR) return false;
  }
  return false;
}

bool SendTcp(const DeliveryConfig& config, const std::string& payload) {
  if (Cancelled(config)) return false;
  Winsock winsock;
  if (!winsock.ok) return false;
  Socket socket;
  if (socket.value == INVALID_SOCKET) return false;
  u_long nonblocking = 1;
  if (ioctlsocket(socket.value, FIONBIO, &nonblocking) == SOCKET_ERROR) return false;
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(static_cast<u_short>(config.port));
  if (InetPtonA(AF_INET, config.ip.c_str(), &address.sin_addr) != 1) return false;
  const auto deadline = Clock::now() + std::chrono::milliseconds(config.timeout_ms);
  if (connect(socket.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
    const auto error = WSAGetLastError();
    if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS) return false;
    if (!WaitSocket(socket.value, true, deadline, config)) return false;
    int status = 0, length = sizeof(status);
    if (getsockopt(socket.value, SOL_SOCKET, SO_ERROR,
                   reinterpret_cast<char*>(&status), &length) == SOCKET_ERROR || status) return false;
  }
  std::size_t sent = 0;
  while (sent < payload.size()) {
    if (!WaitSocket(socket.value, true, deadline, config)) return false;
    const auto chunk = static_cast<int>((std::min)(payload.size() - sent, std::size_t{65536}));
    const int count = send(socket.value, payload.data() + sent, chunk, 0);
    if (count > 0) sent += static_cast<std::size_t>(count);
    else if (count == 0 || WSAGetLastError() != WSAEWOULDBLOCK) return false;
  }
  if (shutdown(socket.value, SD_SEND) == SOCKET_ERROR) return false;
  if (!WaitSocket(socket.value, false, deadline, config)) return false;
  char reply[1024];
  return recv(socket.value, reply, sizeof(reply), 0) != SOCKET_ERROR;
}

struct Delivery {
  std::string payload;
  std::shared_ptr<const DeliveryConfig> config;
  Delivery() { ++State().deliveries; }
  ~Delivery() { --State().deliveries; }
};
void CALLBACK Deliver(PTP_CALLBACK_INSTANCE, PVOID context, PTP_WORK) {
  std::unique_ptr<Delivery> delivery(static_cast<Delivery*>(context));
  if (!delivery || Cancelled(*delivery->config)) return;
  try {
    if (delivery->config->http) {
#ifdef WXHELPER_HOOK_TESTING
      testing::SendHttp(delivery->payload);
#else
      HttpClient::GetInstance().SendRequest(delivery->payload);
#endif
    } else if (!SendTcp(*delivery->config, delivery->payload) && !Cancelled(*delivery->config)) {
      SPDLOG_WARN("TCP hook delivery failed or timed out");
    }
  } catch (...) {
    OutputDebugStringA("wxhelper: hook delivery failed.");
  }
}
bool Queue(std::string payload, std::shared_ptr<const DeliveryConfig> config) {
  if (!config) return false;
  auto delivery = std::make_unique<Delivery>();
  delivery->payload = std::move(payload);
  delivery->config = std::move(config);
  if (!ThreadPool::GetInstance().AddWork(Deliver, delivery.get())) return false;
  delivery.release();
  return true;
}

UINT64 HandleSyncMsg(UINT64 first, UINT64 second, UINT64 third) {
  CallbackGuard callback;
  if (callback.messages) {
    try {
      nlohmann::json msg;
      msg["pid"] = GetCurrentProcessId();
      msg["fromUser"] = Utils::ReadSKBuiltinString(*reinterpret_cast<INT64*>(second + 0x18));
      msg["toUser"] = Utils::ReadSKBuiltinString(*reinterpret_cast<INT64*>(second + 0x28));
      msg["content"] = Utils::ReadSKBuiltinString(*reinterpret_cast<INT64*>(second + 0x30));
      msg["signature"] = Utils::ReadWeChatStr(*reinterpret_cast<INT64*>(second + 0x48));
      msg["msgId"] = *reinterpret_cast<INT64*>(second + 0x60);
      msg["msgSequence"] = *reinterpret_cast<DWORD*>(second + 0x5c);
      msg["createTime"] = *reinterpret_cast<DWORD*>(second + 0x58);
      msg["displayFullContent"] = Utils::ReadWeChatStr(*reinterpret_cast<INT64*>(second + 0x50));
      const auto type = *reinterpret_cast<DWORD*>(second + 0x24);
      msg["type"] = type;
      if (type == 3) msg["base64Img"] = base64_encode(Utils::ReadSKBuiltinBuffer(*reinterpret_cast<INT64*>(second + 0x40)));
      if (!Queue(msg.dump() + '\n', callback.config)) SPDLOG_WARN("Message work rejected");
    } catch (...) { OutputDebugStringA("wxhelper: message capture failed; forwarding native call."); }
  }
  return original_message(first, second, third);
}

UINT64 HandleSNSMsg(UINT64 first, UINT64 second, UINT64 third) {
  CallbackGuard callback;
  if (callback.messages) {
    try {
      nlohmann::json message = {{"data", nlohmann::json::array()}};
      auto begin = *reinterpret_cast<UINT64*>(second + 0x30);
      const auto end = *reinterpret_cast<UINT64*>(second + 0x38);
      while (begin && begin < end) {
        nlohmann::json item;
        item["snsId"] = *reinterpret_cast<UINT64*>(begin);
        item["createTime"] = *reinterpret_cast<DWORD*>(begin + 0x38);
        item["senderId"] = Utils::ReadWstringThenConvert(begin + 0x18);
        item["content"] = Utils::ReadWstringThenConvert(begin + 0x48);
        item["xml"] = Utils::ReadWstringThenConvert(begin + 0x580);
        message["data"].push_back(std::move(item));
        begin += 0x11e0;
      }
      if (!Queue(message.dump() + '\n', callback.config)) SPDLOG_WARN("SNS work rejected");
    } catch (...) { OutputDebugStringA("wxhelper: SNS capture failed; forwarding native call."); }
  }
  return original_sns(first, second, third);
}

UINT64 HandlePrintLog(UINT64 a, UINT64 b, UINT64 c, UINT64 d, UINT64 e, UINT64 f,
                       UINT64 g, UINT64 h, UINT64 i, UINT64 j, UINT64 k, UINT64 l) {
  CallbackGuard callback;
  const auto result = original_log(a, b, c, d, e, f, g, h, i, j, k, l);
  if (callback.log && result > 1) {
    try {
      const auto wide = Utils::UTF8ToWstring(std::string(reinterpret_cast<char*>(result)));
      spdlog::info("wechat log:{}", Utils::WstringToAnsi(wide, CP_ACP));
    } catch (...) { OutputDebugStringA("wxhelper: log capture failed."); }
  }
  return result;
}

Change MessageChange(bool attach) { return {reinterpret_cast<PVOID*>(&original_message), reinterpret_cast<PVOID>(HandleSyncMsg), attach}; }
Change SnsChange(bool attach) { return {reinterpret_cast<PVOID*>(&original_sns), reinterpret_cast<PVOID>(HandleSNSMsg), attach}; }
Change LogChange(bool attach) { return {reinterpret_cast<PVOID*>(&original_log), reinterpret_cast<PVOID>(HandlePrintLog), attach}; }

bool ResolveOriginals() {
#ifdef WXHELPER_HOOK_TESTING
  return original_message && original_sns && original_log;
#else
  const auto base = Utils::GetWeChatWinBase();
  if (!base) return false;
  if (!State().messages) {
    original_message = reinterpret_cast<MessageFunction>(base + offset::kDoAddMsg);
    original_sns = reinterpret_cast<MessageFunction>(base + offset::kOnSnsTimeLineSceneFinish);
  }
  if (!State().log) original_log = reinterpret_cast<LogFunction>(base + offset::kHookLog);
  return true;
#endif
}
}  // namespace

int HookSyncMsg(std::string ip, int port, std::string url, uint64_t timeout, bool http) {
  if (callback_depth) return ERROR_BUSY;
  Transition transition;
  auto& state = State();
  if (state.stopping) return ERROR_OPERATION_ABORTED;
  if (state.messages) return 2;
  // A previous registration can still have accepted deliveries. Do not change
  // HttpClient's destination underneath those queued requests.
  if (state.deliveries.load()) return ERROR_BUSY;
  if (!ResolveOriginals()) return -1;
  auto config = std::make_shared<DeliveryConfig>();
  config->http = http;
  config->timeout_ms = timeout ? timeout : 5000;
  config->cancelled = &state.stopping;
  if (config->timeout_ms > 60000) return ERROR_INVALID_PARAMETER;
  if (http) {
#ifdef WXHELPER_HOOK_TESTING
    if (!testing::ConfigureHttp(url, timeout)) return ERROR_INVALID_PARAMETER;
#else
    if (!HttpClient::GetInstance().SetConfig(url, timeout)) return ERROR_INVALID_PARAMETER;
#endif
  } else {
    Winsock winsock;
    IN_ADDR address{};
    if (!winsock.ok || port < 1 || port > 65535 || InetPtonA(AF_INET, ip.c_str(), &address) != 1)
      return ERROR_INVALID_PARAMETER;
    config->ip = std::move(ip);
    config->port = port;
  }
  const auto result = ApplyChanges({MessageChange(true), SnsChange(true)});
  if (result == NO_ERROR) { state.messages = true; state.config = std::move(config); }
  return result;
}

int UnHookSyncMsg() {
  if (callback_depth) return ERROR_BUSY;
  Transition transition;
  if (!State().messages) return NO_ERROR;
  const auto result = ApplyChanges({MessageChange(false), SnsChange(false)});
  if (result == NO_ERROR) { State().messages = false; State().config.reset(); }
  return result;
}
int HookLog() {
  if (callback_depth) return ERROR_BUSY;
  Transition transition;
  if (State().stopping) return ERROR_OPERATION_ABORTED;
  if (State().log) return 2;
  if (!ResolveOriginals()) return -1;
  const auto result = ApplyChanges({LogChange(true)});
  if (result == NO_ERROR) State().log = true;
  return result;
}
int UnHookLog() {
  if (callback_depth) return ERROR_BUSY;
  Transition transition;
  if (!State().log) return NO_ERROR;
  const auto result = ApplyChanges({LogChange(false)});
  if (result == NO_ERROR) State().log = false;
  return result;
}
int StopAll() {
  if (callback_depth) return ERROR_BUSY;
  Transition transition(true);
  auto& state = State();
  LONG result = NO_ERROR;
  if (state.messages && state.log) result = ApplyChanges({MessageChange(false), SnsChange(false), LogChange(false)});
  else if (state.messages) result = ApplyChanges({MessageChange(false), SnsChange(false)});
  else if (state.log) result = ApplyChanges({LogChange(false)});
  if (result == NO_ERROR) { state.messages = false; state.log = false; state.config.reset(); }
  return result;
}

#ifdef WXHELPER_HOOK_TESTING
namespace testing {
void Reset(MessageFunction message, MessageFunction sns, LogFunction log) {
  Transition transition;
  State().messages = false; State().log = false; State().stopping = false;
  State().config.reset();
  original_message = message; original_sns = sns; original_log = log;
}
bool MessagesInstalled() { std::lock_guard<std::mutex> lock(State().mutex); return State().messages; }
bool LogInstalled() { std::lock_guard<std::mutex> lock(State().mutex); return State().log; }
bool Stopping() { return State().stopping.load(); }
std::size_t PendingDeliveries() { return State().deliveries.load(); }
long WinsockReferences() { return owned_winsock_references.load(); }
UINT64 InvokeMessage(UINT64 a, UINT64 b, UINT64 c) { return HandleSyncMsg(a, b, c); }
UINT64 InvokeSns(UINT64 a, UINT64 b, UINT64 c) { return HandleSNSMsg(a, b, c); }
bool QueuePayload(std::string payload) {
  CallbackGuard callback;
  return callback.messages && Queue(std::move(payload), callback.config);
}
bool SendTcpPayload(std::string ip, int port, std::uint64_t timeout, const std::string& payload) {
  DeliveryConfig config; config.ip = std::move(ip); config.port = port; config.timeout_ms = timeout;
  return SendTcp(config, payload);
}
}  // namespace testing
#endif
}  // namespace wxhelper::hooks
