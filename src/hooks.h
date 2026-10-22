#ifndef WXHELPER_HOOKS_H_
#define WXHELPER_HOOKS_H_
#include "Windows.h"
#include "wechat_function.h"
namespace wxhelper {
namespace hooks {

int HookSyncMsg(std::string client_ip, int port, std::string url, uint64_t timeout,
                bool enable);

int UnHookSyncMsg();

int HookLog();

int UnHookLog();

// Permanently reject registrations/capture, drain active native hook callbacks,
// and detach all installed hooks in one transaction. Returns a Windows error
// code on failure and preserves installed state for retry. Native forwarding
// continues even while stopping. Does not stop HTTP/pool or unload the pinned DLL.
// Never call from DllMain or from within a native hook callback.
int StopAll();

#ifdef WXHELPER_HOOK_TESTING
namespace testing {
using MessageFunction = UINT64 (*)(UINT64, UINT64, UINT64);
using LogFunction = UINT64 (*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64,
                              UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);
void Reset(MessageFunction, MessageFunction, LogFunction);
bool MessagesInstalled();
bool LogInstalled();
bool Stopping();
std::size_t PendingDeliveries();
long WinsockReferences();
UINT64 InvokeMessage(UINT64, UINT64, UINT64);
UINT64 InvokeSns(UINT64, UINT64, UINT64);
bool QueuePayload(std::string);
bool SendTcpPayload(std::string, int, std::uint64_t, const std::string&);
// Implemented by the isolated test executable, never by the live DLL.
bool ConfigureHttp(const std::string&, std::uint64_t);
void SendHttp(const std::string&);
}
#endif

}  // namespace hooks
}  // namespace wxhelper
#endif
