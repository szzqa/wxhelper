#include "client_compatibility.h"
#include <iostream>

int wmain(int argc, wchar_t** argv) {
  if (argc != 2) {
    std::wcerr << L"Usage: wxhelper_probe <absolute path to client DLL>\n";
    return 1;
  }
  const auto result = wxhelper::InspectClientFile(argv[1]);
  std::wcout << L"Module: " << result.path << L"\nVersion: " << result.version
             << L"\nMachine: 0x" << std::hex << result.machine
             << L"\nSupported: " << (result.supported ? L"yes" : L"no")
             << L"\n" << result.reason << L"\n";
  return result.supported ? 0 : 2;
}
