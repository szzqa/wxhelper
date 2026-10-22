#include <WinSock2.h>
#include <Windows.h>
#include <WS2tcpip.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <nlohmann/json.hpp>

namespace {
using Clock = std::chrono::steady_clock;

class Winsock {
 public:
  Winsock() {
    WSADATA data{};
    const int error = WSAStartup(MAKEWORD(2, 2), &data);
    if (error) throw std::runtime_error("WSAStartup failed: " + std::to_string(error));
  }
  ~Winsock() { WSACleanup(); }
};

class Socket {
 public:
  Socket() : value_(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) {}
  ~Socket() { Close(); }
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  SOCKET get() const { return value_; }
  void Close() {
    if (value_ != INVALID_SOCKET) {
      closesocket(value_);
      value_ = INVALID_SOCKET;
    }
  }

 private:
  SOCKET value_;
};

class CurrentDirectory {
 public:
  explicit CurrentDirectory(const std::filesystem::path& path)
      : previous_(std::filesystem::current_path()) {
    std::filesystem::current_path(path);
  }
  ~CurrentDirectory() {
    std::error_code ignored;
    std::filesystem::current_path(previous_, ignored);
  }

 private:
  std::filesystem::path previous_;
};

int Fail(int code, const char* message, DWORD error = 0) {
  std::cerr << message;
  if (error) std::cerr << " (error " << error << ")";
  std::cerr << std::endl;
  return code;
}

bool WaitSocket(SOCKET socket, bool writing, Clock::time_point deadline) {
  const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(
      deadline - Clock::now()).count();
  if (remaining <= 0) return false;
  timeval timeout{};
  timeout.tv_sec = static_cast<long>(remaining / 1000000);
  timeout.tv_usec = static_cast<long>(remaining % 1000000);
  fd_set ready;
  FD_ZERO(&ready);
  FD_SET(socket, &ready);
  return select(0, writing ? nullptr : &ready, writing ? &ready : nullptr,
                nullptr, &timeout) > 0;
}

bool ConnectLoopback(Socket& client, unsigned short port, Clock::time_point deadline) {
  if (client.get() == INVALID_SOCKET) return false;
  u_long nonblocking = 1;
  if (ioctlsocket(client.get(), FIONBIO, &nonblocking) == SOCKET_ERROR) return false;
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(port);
  if (connect(client.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
    if (WSAGetLastError() != WSAEWOULDBLOCK || !WaitSocket(client.get(), true, deadline)) return false;
    int connection_error = 0;
    int size = sizeof(connection_error);
    if (getsockopt(client.get(), SOL_SOCKET, SO_ERROR,
                   reinterpret_cast<char*>(&connection_error), &size) == SOCKET_ERROR ||
        connection_error != 0) return false;
  }
  return true;
}

struct Response {
  int status = 0;
  nlohmann::json body;
};

bool Request(unsigned short port, const std::string& method, const std::string& path,
             const std::string& body, Clock::time_point deadline, Response& output) {
  output = {};
  Socket client;
  if (!ConnectLoopback(client, port, deadline)) return false;
  const std::string request = method + " " + path +
      " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
      "Content-Type: application/json\r\nContent-Length: " +
      std::to_string(body.size()) + "\r\n\r\n" + body;
  size_t sent = 0;
  while (sent < request.size()) {
    if (!WaitSocket(client.get(), true, deadline)) return false;
    const int count = send(client.get(), request.data() + sent,
                           static_cast<int>(request.size() - sent), 0);
    if (count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
    if (count <= 0) return false;
    sent += static_cast<size_t>(count);
  }
  std::string response;
  while (response.size() < 65536) {
    if (!WaitSocket(client.get(), false, deadline)) return false;
    char buffer[1024];
    const int count = recv(client.get(), buffer, sizeof(buffer), 0);
    if (count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
    if (count <= 0) return false;
    response.append(buffer, count);
    const auto headers_end = response.find("\r\n\r\n");
    if (headers_end == std::string::npos) continue;
    const auto length_field = response.find("\r\nContent-Length:");
    if (length_field == std::string::npos || length_field > headers_end)
      throw std::runtime_error("Fixture response must declare Content-Length.");
    const auto length = std::stoull(response.substr(length_field + 17));
    if (length > 65536) throw std::runtime_error("Fixture response exceeds its size limit.");
    const auto body_start = headers_end + 4;
    if (response.size() < body_start + length) continue;
    if (response.compare(0, 9, "HTTP/1.1 ") != 0)
      throw std::runtime_error("Unexpected HTTP response protocol.");
    output.status = std::stoi(response.substr(9, 3));
    output.body = nlohmann::json::parse(response.substr(body_start, static_cast<size_t>(length)));
    return true;
  }
  return false;
}

Response RequireResponse(unsigned short port, const std::string& method,
                         const std::string& path, const std::string& body, int status) {
  Response response;
  if (!Request(port, method, path, body, Clock::now() + std::chrono::seconds(2), response))
    throw std::runtime_error("Incomplete response from " + method + " " + path);
  if (response.status != status)
    throw std::runtime_error(method + " " + path + " expected HTTP " + std::to_string(status) +
                             ", got " + std::to_string(response.status) + ": " + response.body.dump());
  return response;
}

bool IsReady(unsigned short port, Clock::time_point deadline) {
  Response response;
  return Request(port, "GET", "/api/health", "", deadline, response) &&
      response.status == 200 && response.body.at("data").at("ready") == true &&
      response.body.at("data").at("state") == "ready";
}

bool PortListening(unsigned short port, Clock::time_point deadline) {
  Socket client;
  return ConnectLoopback(client, port, deadline);
}

int Run(int argc, wchar_t** argv) {
  if (argc != 3 && argc != 4) {
    return Fail(1, "Usage: startup_lifetime_test <legacy fixture DLL> <wxhelper DLL> [artifact directory]");
  }
  // Resolve arguments before changing this test process's working directory.
  const auto fixture_path = std::filesystem::absolute(argv[1]);
  const auto helper_path = std::filesystem::absolute(argv[2]);
  const auto root = argc == 4 ? std::filesystem::absolute(argv[3]) :
                               std::filesystem::temp_directory_path();
  std::filesystem::create_directories(root);
  std::filesystem::path work_directory;
  for (int attempt = 0; attempt < 8; ++attempt) {
    auto candidate = root / (L"wxhelper-startup-" + std::to_wstring(GetCurrentProcessId()) +
        L"-" + std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(attempt));
    if (std::filesystem::create_directory(candidate)) {
      work_directory = std::move(candidate);
      break;
    }
  }
  if (work_directory.empty()) return Fail(2, "Cannot allocate isolated test directory.");
  // Retain artifacts: the pinned DLL owns its log file until process teardown.
  std::wcout << L"Startup artifacts: " << work_directory.wstring() << std::endl;
  CurrentDirectory directory(work_directory);
  if (!SetEnvironmentVariableW(L"WXHELPER_DATA_DIR", work_directory.c_str()))
    return Fail(2, "Cannot set isolated helper data directory.", GetLastError());
  Winsock winsock;

  Socket reservation;
  if (reservation.get() == INVALID_SOCKET) return Fail(3, "Cannot create port reservation socket.", WSAGetLastError());
  BOOL exclusive = TRUE;
  if (setsockopt(reservation.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                 reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) == SOCKET_ERROR) {
    return Fail(3, "Cannot reserve an exclusive port.", WSAGetLastError());
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (bind(reservation.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
    return Fail(3, "Cannot bind the port reservation.", WSAGetLastError());
  }
  int address_size = sizeof(address);
  if (getsockname(reservation.get(), reinterpret_cast<sockaddr*>(&address), &address_size) == SOCKET_ERROR) {
    return Fail(3, "Cannot read the reserved port.", WSAGetLastError());
  }
  const unsigned short port = ntohs(address.sin_port);
  {
    std::ofstream config(work_directory / L"config.ini");
    config << "[config]\nPort=" << port << "\n";
    config.close();
    if (!config) return Fail(4, "Cannot write isolated config.ini.");
  }

  // The fixture must stay loaded for the lifetime of the pinned helper. Its
  // module reference, like the helper's, is reclaimed when this host exits.
  HMODULE fixture = LoadLibraryW(fixture_path.c_str());
  if (!fixture) return Fail(5, "Cannot load the inert legacy fixture.", GetLastError());
  reservation.Close();
  HMODULE helper = LoadLibraryW(helper_path.c_str());
  if (!helper) {
    const DWORD error = GetLastError();
    FreeLibrary(fixture);
    return Fail(6, "Helper rejected the supported legacy fixture.", error);
  }
  const auto deadline = Clock::now() + std::chrono::seconds(5);
  bool ready = false;
  while (Clock::now() < deadline) {
    if (IsReady(port, (std::min)(deadline, Clock::now() + std::chrono::milliseconds(250)))) {
      ready = true;
      break;
    }
    if (Clock::now() < deadline) Sleep(10);
  }
  if (!ready) return Fail(7, "Helper did not report ready through /api/health within five seconds.");
  const auto health = RequireResponse(port, "GET", "/api/health", "", 200);
  if (health.body.at("data").at("dllPinned") != true ||
      health.body.at("data").at("dynamicUnload") != false)
    return Fail(11, "Health reported incorrect module lifetime capabilities.");
  const auto capabilities = RequireResponse(port, "GET", "/api/capabilities", "", 200);
  if (capabilities.body.at("data").at("weixin4Runtime") != false ||
      capabilities.body.at("data").at("deliveryConfirmation") != false)
    return Fail(12, "Capabilities advertised unimplemented runtime/delivery support.");

  // These inputs must be rejected BEFORE business dispatch. The inert fixture
  // has no valid WeChat function offsets. Never send a valid business request.
  RequireResponse(port, "GET", "/api/checkLogin", "", 405);
  RequireResponse(port, "POST", "/api/no-such-fixture-route", "{}", 404);
  RequireResponse(port, "POST", "/api/sendTextMsg", R"({"wxid":"fixture-only"})", 400);
  RequireResponse(port, "POST", "/api/topMsg", R"({"msgId":"18446744073709551616"})", 400);
  RequireResponse(port, "POST", "/api/hookSyncMsg",
                  R"({"ip":"127.0.0.1","port":2147483648,"enableHttp":0})", 400);
  RequireResponse(port, "POST", "/api/test", "{}", 501);
  RequireResponse(port, "GET", "/api/stop", "", 405);
  RequireResponse(port, "POST", "/api/stop", "{", 400);
  RequireResponse(port, "POST", "/api/stop", "[]", 400);
  if (!IsReady(port, Clock::now() + std::chrono::seconds(2)))
    return Fail(13, "Invalid requests changed readiness or stopped the helper.");
  if (!FreeLibrary(helper)) return Fail(8, "FreeLibrary(helper) failed.", GetLastError());
  if (GetModuleHandleW(helper_path.filename().c_str()) != helper) {
    return Fail(9, "Helper was not pinned after successful initialization.");
  }
  // Stop is a control-only operation: there are no installed hooks or real
  // messages in this process. Its complete 202 JSON must arrive before closure.
  const auto stop_deadline = Clock::now() + std::chrono::seconds(5);
  const auto stopped = RequireResponse(port, "POST", "/api/stop", "{}", 202);
  if (stopped.body.at("data").at("state") != "stopping" ||
      stopped.body.at("data").at("dllPinned") != true)
    return Fail(14, "Stop acknowledgement was incomplete or incorrect.");
  bool closed = false;
  while (Clock::now() < stop_deadline) {
    if (!PortListening(port, (std::min)(stop_deadline,
                       Clock::now() + std::chrono::milliseconds(200)))) {
      closed = true;
      break;
    }
    Sleep(10);
  }
  if (!closed) return Fail(15, "HTTP listener remained active five seconds after stop.");
  if (GetModuleHandleW(helper_path.filename().c_str()) != helper)
    return Fail(16, "Stopping the service unexpectedly removed the pinned DLL.");
  std::cout << "PASS: real loopback health/capabilities, rejected business inputs, complete stop reply, closed listener and retained module pin."
            << std::endl;
  // Do not terminate the host: CTest's timeout must expose a teardown deadlock.
  return 0;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  try {
    return Run(argc, argv);
  } catch (const std::exception& error) {
    return Fail(10, error.what());
  }
}
