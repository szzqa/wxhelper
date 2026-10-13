#include "client_compatibility.h"

#include <filesystem>
#include <fstream>
#include <vector>

namespace wxhelper {
ClientCompatibility InspectClientFile(const std::wstring& path) {
  ClientCompatibility result;
  result.path = path;
  std::ifstream input(std::filesystem::path(path), std::ios::binary);
  IMAGE_DOS_HEADER dos{};
  DWORD signature = 0;
  IMAGE_FILE_HEADER coff{};
  WORD optional_magic = 0;
  if (!input.read(reinterpret_cast<char*>(&dos), sizeof(dos)) ||
      dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < sizeof(dos)) {
    result.reason = L"Cannot read a valid PE header.";
    return result;
  }
  input.seekg(dos.e_lfanew);
  if (!input.read(reinterpret_cast<char*>(&signature), sizeof(signature)) ||
      signature != IMAGE_NT_SIGNATURE ||
      !input.read(reinterpret_cast<char*>(&coff), sizeof(coff)) ||
      !input.read(reinterpret_cast<char*>(&optional_magic), sizeof(optional_magic))) {
    result.reason = L"Invalid or truncated PE header.";
    return result;
  }
  result.machine = coff.Machine;
  DWORD ignored = 0;
  DWORD size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
  std::vector<BYTE> bytes(size);
  VS_FIXEDFILEINFO* version = nullptr;
  UINT version_size = 0;
  if (!size || !GetFileVersionInfoW(path.c_str(), 0, size, bytes.data()) ||
      !VerQueryValueW(bytes.data(), L"\\", reinterpret_cast<void**>(&version),
                      &version_size) ||
      version_size < sizeof(*version) || version->dwSignature != 0xfeef04bd) {
    result.reason = L"No valid file version resource; refusing unknown offsets.";
    return result;
  }
  result.version = std::to_wstring(HIWORD(version->dwFileVersionMS)) + L"." +
                   std::to_wstring(LOWORD(version->dwFileVersionMS)) + L"." +
                   std::to_wstring(HIWORD(version->dwFileVersionLS)) + L"." +
                   std::to_wstring(LOWORD(version->dwFileVersionLS));
  const auto name = std::filesystem::path(path).filename().wstring();
  if (coff.Machine != IMAGE_FILE_MACHINE_AMD64 ||
      optional_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    result.reason = L"This backend requires an AMD64 PE32+ client.";
  } else if (_wcsicmp(name.c_str(), kSupportedModule) != 0 ||
             result.version != kSupportedVersion) {
    result.reason = L"No verified backend for this client. Only WeChatWin.dll "
                    L"3.9.5.81 x64 has an offset table; Weixin 4.x needs a new backend.";
  } else {
    result.supported = true;
    result.reason = L"Matches the legacy 3.9.5.81 x64 offset profile. "
                    L"Version matching alone does not validate modified binaries.";
  }
  return result;
}

ClientCompatibility InspectLoadedClient() {
  // Prefer detecting the incompatible current client if both names are loaded.
  HMODULE module = GetModuleHandleW(L"Weixin.dll");
  if (!module) module = GetModuleHandleW(kSupportedModule);
  if (!module) {
    ClientCompatibility result;
    result.reason = L"Neither WeChatWin.dll nor Weixin.dll is loaded.";
    return result;
  }
  std::vector<wchar_t> path(32768);
  const DWORD length = GetModuleFileNameW(module, path.data(),
                                         static_cast<DWORD>(path.size()));
  if (!length || length >= path.size()) {
    ClientCompatibility result;
    result.reason = L"Unable to identify the loaded client module.";
    return result;
  }
  auto result = InspectClientFile(std::wstring(path.data(), length));
  result.module = module;
  return result;
}
}  // namespace wxhelper
