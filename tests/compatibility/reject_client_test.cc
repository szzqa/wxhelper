#include <Windows.h>
#include <iostream>

// Loads only our inert fixture, never the installed Weixin.dll.
int wmain(int argc, wchar_t** argv) {
  if (argc != 3) return 1;
  HMODULE fixture = LoadLibraryW(argv[1]);
  if (!fixture) return 2;
  HMODULE helper = LoadLibraryW(argv[2]);
  const DWORD error = GetLastError();
  if (helper) {
    std::wcerr << L"Unexpectedly admitted an unsupported client.\n";
    return 3;
  }
  FreeLibrary(fixture);
  if (error != ERROR_DLL_INIT_FAILED) {
    std::wcerr << L"Expected DllMain rejection; actual error: " << error << L"\n";
    return 4;
  }
  return 0;
}
