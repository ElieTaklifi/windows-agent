#include "inventory.h"
#include <windows.h>
#include <sddl.h>
#include <lmcons.h>

static std::string sidToUsername(const std::string& sid) {
    PSID pSid = nullptr;
    if (!ConvertStringSidToSidA(sid.c_str(), &pSid))
        return "";

    char name[UNLEN + 1];
    char domain[UNLEN + 1];
    DWORD nameLen = UNLEN + 1;
    DWORD domainLen = UNLEN + 1;
    SID_NAME_USE use;

    std::string result;

    if (LookupAccountSidA(nullptr, pSid, name, &nameLen, domain, &domainLen, &use))
        result = std::string(domain) + "\\" + name;

    LocalFree(pSid);
    return result;
}

static void readUninstallKey(
    HKEY root,
    const std::string& subPath,
    const std::string& scope,
    const std::string& user,
    JsonBuilder& builder)
{
    HKEY hKey;
    if (RegOpenKeyExA(root, subPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    char subKeyName[256];
    DWORD index = 0;

    while (true) {
        DWORD subKeySize = sizeof(subKeyName);
        if (RegEnumKeyExA(hKey, index++, subKeyName, &subKeySize,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;

        HKEY hSubKey;
        if (RegOpenKeyExA(hKey, subKeyName, 0, KEY_READ, &hSubKey) != ERROR_SUCCESS)
            continue;

        char name[512];
        DWORD size = sizeof(name);

        if (RegQueryValueExA(hSubKey, "DisplayName", nullptr, nullptr,
                             (LPBYTE)name, &size) == ERROR_SUCCESS) {

            ApplicationRecord app;
            app.scope = scope;
            app.user = user;
            app.name = name;

            char buffer[512];

            size = sizeof(buffer);
            if (RegQueryValueExA(hSubKey, "DisplayVersion", nullptr, nullptr,
                                 (LPBYTE)buffer, &size) == ERROR_SUCCESS)
                app.version = buffer;

            size = sizeof(buffer);
            if (RegQueryValueExA(hSubKey, "Publisher", nullptr, nullptr,
                                 (LPBYTE)buffer, &size) == ERROR_SUCCESS)
                app.publisher = buffer;

            size = sizeof(buffer);
            if (RegQueryValueExA(hSubKey, "InstallLocation", nullptr, nullptr,
                                 (LPBYTE)buffer, &size) == ERROR_SUCCESS)
                app.installPath = buffer;

            builder.addApplication(app);
        }

        RegCloseKey(hSubKey);
    }

    RegCloseKey(hKey);
}

static void enumeratePerUser(JsonBuilder& builder) {
    HKEY hUsers;
    if (RegOpenKeyExA(HKEY_USERS, nullptr, 0, KEY_READ, &hUsers) != ERROR_SUCCESS)
        return;

    char sid[256];
    DWORD index = 0;

    while (true) {
        DWORD sidSize = sizeof(sid);
        if (RegEnumKeyExA(hUsers, index++, sid, &sidSize,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;

        if (strncmp(sid, "S-1-5-", 6) != 0)
            continue;

        std::string user = sidToUsername(sid);
        if (user.empty())
            continue;

        std::string path = std::string(sid) +
            "\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

        readUninstallKey(HKEY_USERS, path, "PerUser", user, builder);
    }

    RegCloseKey(hUsers);
}

void enumerateInstalledApplications(JsonBuilder& builder) {
    readUninstallKey(
        HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "System",
        "",
        builder);

    readUninstallKey(
        HKEY_LOCAL_MACHINE,
        "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "System32",
        "",
        builder);

    enumeratePerUser(builder);
}


//need to add HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall
//need to add Microsoft Store (UWP / MSIX) apps using powershell Get-AppxPackage
// Drivers and kernel components: HKLM\SYSTEM\CurrentControlSet\Services
// Services installed manually
// Scheduled-task–based persistence Software launched via: Task Scheduler, startup folder, Registry Run keys -> None require uninstall registration.
// MSI edge cases : Some MSI packages:Suppress ARP entries Use ARPSYSTEMCOMPONENT=1 Result: installed, but hidden.