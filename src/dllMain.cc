#include "pch.h"
#include "global_context.h"
#include "utils.h"
#include "client_compatibility.h"


using namespace wxhelper;

namespace {
DWORD WINAPI InitializeHelper(LPVOID module) {
  try {
    GlobalContext::GetInstance().initialize(static_cast<HMODULE>(module));
  } catch (const std::exception& error) {
    OutputDebugStringA(error.what());
  } catch (...) {
    OutputDebugStringA("wxhelper initialization failed.");
  }
  return 0;
}
}  // namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
      DisableThreadLibraryCalls(hModule);
      // Reject BEFORE any manager, database, hook or HTTP server is created.
      try {
        const auto client = InspectLoadedClient();
        if (!client.supported) {
          OutputDebugStringW((L"wxhelper: " + client.reason).c_str());
          return FALSE;
        }
      } catch (...) {
        return FALSE;
      }
      // Reserve a worker before pinning: allocation failure must not leave a
      // permanently loaded helper that can never initialize.
      HANDLE worker = CreateThread(nullptr, 0, InitializeHelper, hModule,
                                   CREATE_SUSPENDED, nullptr);
      if (!worker) return FALSE;
      // Hooks and asynchronous callbacks require process lifetime ownership.
      // Pinning makes FreeLibrary harmless; stop the helper by exiting WeChat.
      HMODULE pinned = nullptr;
      if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                 GET_MODULE_HANDLE_EX_FLAG_PIN,
                             reinterpret_cast<LPCWSTR>(hModule), &pinned)) {
        // This owned thread has never executed user code or acquired a lock.
        TerminateThread(worker, ERROR_DLL_INIT_FAILED);
        CloseHandle(worker);
        return FALSE;
      }
      // The worker starts only after the loader lock is released. Never wait
      // for thread startup/exit from DllMain.
      if (ResumeThread(worker) == static_cast<DWORD>(-1)) {
        TerminateThread(worker, ERROR_DLL_INIT_FAILED);
        OutputDebugStringA("wxhelper: failed to resume initialization; restart the client.");
      }
      CloseHandle(worker);
      break;
    }
    case DLL_THREAD_ATTACH: {
      break;
    }
    case DLL_THREAD_DETACH: {
      break;
    }
    case DLL_PROCESS_DETACH: {
      // A successfully initialized module is pinned until process termination.
      // Joining threads here would deadlock against the loader lock.
      break;
    }
  }
  return TRUE;
}
