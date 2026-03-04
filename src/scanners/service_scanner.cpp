#include "service_scanner.h"

#include <stdexcept>

#ifdef _WIN32
#include <windows.h>
#include <string>
#include <vector>

// tells linker to automatically link the program to ther lib for using registry-related API
#pragma comment(lib, "advapi32.lib") 

namespace {

DWORD readRegDword(HKEY key, const char* name, DWORD fallback = 0xFFFFFFFF) {
    DWORD value = 0;
    DWORD type = 0;
    DWORD size = sizeof(value);
    if (RegQueryValueExA(key, name, nullptr, &type, 
                          reinterpret_cast<LPBYTE>(&value), &size) != ERROR_SUCCESS)
        return fallback;
    if (type != REG_DWORD)
        return fallback;
    return value;
}

static const char* kServicesPath = "SYSTEM\\CurrentControlSet\\Services";

void enumerateServices(std::vector<RawSoftwareEntry>& entries){
    HKEY base = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, kServicesPath, 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS, &base) != ERROR_SUCCESS)
        return;

    char subkeyBuf[256] = {};
    for (DWORD index = 0; ; ++index) {
        DWORD subKeySize = static_cast<DWORD>(sizeof(subkeyBuf));
        const LONG rc = RegEnumKeyExA(base, index, subkeyBuf, &subKeySize,
                                       nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS)    continue;
        
        HKEY sub = nullptr;
        if (RegOpenKeyExA(base, subkeyBuf, 0, KEY_READ, &sub) != ERROR_SUCCESS)
            continue;
        
        // Read all value for this service subkey

        const DWORD rawType = readRegDword(sub, "Type", 0);
        const DWORD rawStart = readRegDword(sub, "Start", SERVICE_DEMAND_START);
        const DWORD rawError = readRegDword(sub, "ErrorControl", SERVICE_ERROR_NORMAL);
        const DWORD rawSidType = readRegDword(sub, "ServiceSidType", 0);
        const DWORD rawTag = readRegDword(sub, "Tag", 0);
    
    }    

}

} // namespace
#endif // _WIN32


std::vector<RawSoftwareEntry> ServiceScanner::scan(){
    std::vector<RawSoftwareEntry> entries;
#ifdef _WIN32
    try {
        enumerateServices(entries);
    }   catch (const std::exception& ex){
        throw std::runtime_error(std::string("ServiceScanner failed: ") + ex.what());
    }
#endif

    return entries;
}
