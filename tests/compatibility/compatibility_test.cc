#include "client_compatibility.h"
#include <iostream>

int wmain(int argc, wchar_t** argv) {
  if (argc != 3) return 1;
  const auto current = wxhelper::InspectClientFile(argv[1]);
  const auto legacy = wxhelper::InspectClientFile(argv[2]);
  const auto absent = wxhelper::InspectClientFile(L"missing-client.dll");
  const auto loaded = wxhelper::InspectLoadedClient();
  if (current.supported || current.version != L"4.1.15.13" ||
      current.machine != IMAGE_FILE_MACHINE_AMD64 || !legacy.supported ||
      legacy.version != L"3.9.5.81" || absent.supported || loaded.supported) {
    std::wcerr << L"Compatibility classification failed.\n";
    return 1;
  }
  return 0;
}
