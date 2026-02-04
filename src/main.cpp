#include <windows.h>

int main() {
    MessageBoxA(
        NULL,
        "Windows Agent is running",
        "windows-agent",
        MB_OK | MB_ICONINFORMATION
    );
    return 0;
}
