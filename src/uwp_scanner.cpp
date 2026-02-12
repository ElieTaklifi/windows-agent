#include "uwp_scanner.h"
#include <windows.h>
#include <string>
#include <vector>


bool UwpScanner::readRegString(
    HKEY hKey,
    const std::wstring& valueName,
    std::wstring& out) {

    DWORD type = 0;
    DWORD size = 0;

    if (RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
        return false;

    if (type != REG_SZ && type != REG_EXPAND_SZ)
        return false;

    std::vector<wchar_t> buffer(size / sizeof(wchar_t));

    if (RegQueryValueExW(hKey, valueName.c_str(), nullptr, nullptr,
    reinterpret_cast<LPBYTE>(buffer.data()), &size) != ERROR_SUCCESS)
        return false;


    out.assign(buffer.data());
    return true;
}

void UwpScanner::splitPackageName(
    const std::wstring& fullName,
    std::wstring& name,
    std::wstring& version) {
    // Format: Name_Version_Arch_PublisherId
    size_t first = fullName.find(L'_');
    if (first == std::wstring::npos) {
        name = fullName;
        version = L"";
        return;
    }


    size_t second = fullName.find(L'_', first + 1);
    name = fullName.substr(0, first);


    if (second != std::wstring::npos)
        version = fullName.substr(first + 1, second - first - 1);
    else
        version = fullName.substr(first + 1);
}

/*
static std::string ws2s(const std::wstring& ws) {
if (ws.empty())
return {};


int size = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
std::string result(size - 1, 0);
WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, result.data(), size, nullptr, nullptr);
return result;
}
*/

void UwpScanner::scan(JsonBuilder& json) {
    HKEY hUsers = nullptr;
    if (RegOpenKeyExW(HKEY_USERS, nullptr, 0, KEY_READ, &hUsers) != ERROR_SUCCESS)
        return;


    DWORD index = 0;
    wchar_t sidName[256];
    DWORD sidSize = 256;

    while (RegEnumKeyExW(hUsers, index++, sidName, &sidSize,
    nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {


        sidSize = 256;
        std::wstring sid(sidName);


        // Skip non-user hives
        if (sid.find(L"_Classes") != std::wstring::npos)
            continue;


        std::wstring packagesPath =
            sid + L"\\Software\\Classes\\Local Settings\\"
                L"Software\\Microsoft\\Windows\\CurrentVersion\\"
                L"AppModel\\Repository\\Packages";


        HKEY hPackages = nullptr;
        if (RegOpenKeyExW(HKEY_USERS, packagesPath.c_str(), 0, KEY_READ, &hPackages) != ERROR_SUCCESS)
            continue;


        DWORD pkgIndex = 0;
        wchar_t pkgName[512];
        DWORD pkgSize = 512;


        while (RegEnumKeyExW(hPackages, pkgIndex++, pkgName, &pkgSize,
            nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {


            pkgSize = 512;
            std::wstring packageFullName(pkgName);


            HKEY hPkg = nullptr;
            if (RegOpenKeyExW(hPackages, packageFullName.c_str(), 0, KEY_READ, &hPkg) != ERROR_SUCCESS)
                continue;


            std::wstring displayName;
            std::wstring publisher;
            std::wstring installPath;


            readRegString(hPkg, L"DisplayName", displayName);
            readRegString(hPkg, L"Publisher", publisher);
            readRegString(hPkg, L"PackageRootFolder", installPath);


            std::wstring name, version;
            splitPackageName(packageFullName, name, version);
            
            //JSON
            ApplicationRecord app;
            app.type = "uwp";
            app.scope = "User";
            app.user = toUtf8(sid);
            app.name = toUtf8(displayName.empty() ? name : displayName);
            app.version = toUtf8(version);
            app.publisher = toUtf8(publisher);
            app.installPath = toUtf8(installPath);
            app.source.type = "registry";
            app.source.location = toUtf8(sid + L"\\" + packageFullName);
            json.addApplication(app);
            
            RegCloseKey(hPkg);
        }

        RegCloseKey(hPackages);

    }

    RegCloseKey(hUsers);
}