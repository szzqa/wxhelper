#ifndef WXHELPER_CLIENT_COMPATIBILITY_H_
#define WXHELPER_CLIENT_COMPATIBILITY_H_

#include <Windows.h>
#include <string>

namespace wxhelper {
inline constexpr wchar_t kSupportedModule[] = L"WeChatWin.dll";
inline constexpr wchar_t kSupportedVersion[] = L"3.9.5.81";

struct ClientCompatibility {
  std::wstring path;
  std::wstring version;
  std::wstring reason;
  WORD machine = 0;
  HMODULE module = nullptr;
  bool supported = false;
};

// Reads file metadata only: never loads or executes the selected client.
ClientCompatibility InspectClientFile(const std::wstring& path);
ClientCompatibility InspectLoadedClient();
}  // namespace wxhelper
#endif
