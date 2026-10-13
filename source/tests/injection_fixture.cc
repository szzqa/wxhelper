#include <Windows.h>

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
#ifdef REJECT_ON_ATTACH
    if (reason == DLL_PROCESS_ATTACH) return FALSE;
#endif
    return TRUE;
}
