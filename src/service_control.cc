#include "pch.h"
#include "service_control.h"
#include "api_validation.h"
#include "global_context.h"
#include <cstring>

namespace {
constexpr unsigned char kStopMarker = 0x71;
void ArmStop(mg_connection* c) {
  const auto deadline = GetTickCount64() + 5000;
  c->data[0] = kStopMarker;
  static_assert(sizeof(c->data) >= 1 + sizeof(deadline));
  std::memcpy(c->data + 1, &deadline, sizeof(deadline));
  // Mongoose closes only after the response buffer drains. CLOSE schedules a
  // separate worker: joining the HTTP event loop from itself would deadlock.
  c->is_draining = 1;
}
}

void HandleControlEvent(mg_connection* c, int event) {
  if (static_cast<unsigned char>(c->data[0]) != kStopMarker) return;
  if (event == MG_EV_POLL) {
    ULONGLONG deadline = 0;
    std::memcpy(&deadline, c->data + 1, sizeof(deadline));
    if (GetTickCount64() >= deadline) c->is_closing = 1;
  } else if (event == MG_EV_CLOSE) {
    c->data[0] = 0;
    wxhelper::GlobalContext::GetInstance().FinishStopAsync();
  }
}

bool HandleControlRequest(mg_connection* c, mg_http_message* hm) {
  const std::string_view path(hm->uri.ptr, hm->uri.len);
  const bool stop = path == "/api/stop";
  const bool health = path == "/api/health";
  if (!stop && !health && path != "/api/capabilities") return false;
  const std::string_view method(hm->method.ptr, hm->method.len);
  bool accepted = false;
  auto& context = wxhelper::GlobalContext::GetInstance();
  auto response = wxhelper::api::ExecuteSafely([&]() {
    if (method != "POST" && (stop || method != "GET"))
      throw wxhelper::api::Error(405, "method_not_allowed", stop ? "use POST" : "use GET or POST");
    if (hm->body.len) {
      const auto body = nlohmann::json::parse(hm->body.ptr, hm->body.ptr + hm->body.len, nullptr, false);
      if (!body.is_object()) throw wxhelper::api::Error(400, "invalid_body", "body must be a valid JSON object");
    }
    if (!stop) return (health ? context.Health() : context.Capabilities()).dump();
    if (!context.PrepareStop())
      throw wxhelper::api::Error(409, "initialization_in_progress", "wait for initialization before stopping");
    accepted = true;
    return nlohmann::json({{"code", 0}, {"msg", "stop accepted"},
        {"data", {{"state", "stopping"}, {"dllPinned", true},
                  {"unload", "exit the host process normally"}}}}).dump();
  });
  if (accepted) response.status = 202;
  const char* headers = stop ? "Content-Type: application/json\r\nAllow: POST\r\nConnection: close\r\n"
      : "Content-Type: application/json\r\nAllow: GET, POST\r\n";
  mg_http_reply(c, response.status, headers, "%s\n", response.body.c_str());
  if (stop) c->is_draining = 1;
  if (accepted) ArmStop(c);
  return true;
}
