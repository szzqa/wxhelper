#include <Windows.h>

// Test-owned host, bounded even when the driver is interrupted.
int main() {
    Sleep(60000);
    return 0;
}
