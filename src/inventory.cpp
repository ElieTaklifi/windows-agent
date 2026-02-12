#include "inventory.h"

#include <windows.h>
#include <lmcons.h>
#include <sddl.h>

#include <string>

static std::string sidToUsername(const std::string& sid) {
    PSID pSid = nullptr;
    if (!ConvertStringSidToSidA(sid.c_str(), &pSid))
        return "";

    char name[UNLEN + 1] = {};
    char domain[UNLEN + 1] = {};
    DWORD nameLen = UNLEN + 1;
    DWORD domainLen = UNLEN + 1;
    SID_NAME_USE use;

    std::string result;
    if (LookupAccountSidA(nullptr, pSid, name, &nameLen, domain, &domainLen, &use)) {
        result = std::string(domain) + "\\" + name;
    }

    LocalFree(pSid);
    return result;
}

static bool readStringValue(HKEY key, const char* valueName, std::string& outValue) {
    outValue.clear();

    DWORD type = 0;
    DWORD size = 0;
    LONG status = RegQueryValueExA(key, valueName, nullptr, &type, nullptr, &size);
    if (status != ERROR_SUCCESS || size == 0)
        return false;

    if (type != REG_SZ && type != REG_EXPAND_SZ)
        return false;

    std::string buffer(size, '\0');
    status = RegQueryValueExA(
        key,
        valueName,
        nullptr,
        nullptr,
        reinterpret_cast<LPBYTE>(&buffer[0]),
        &size);

    if (status != ERROR_SUCCESS)
        return false;

    if (!buffer.empty() && buffer.back() == '\0')
        buffer.pop_back();

    outValue = buffer;
    return true;
}

static std::string makeRegistryPath(const std::string& basePath, const std::string& leaf) {
    return basePath + "\\" + leaf;
}

static void readUninstallKey(
    HKEY root,
    const std::string& subPath,
    const std::string& scope,
    const std::string& user,
    JsonBuilder& builder) {
    HKEY hKey;
    if (RegOpenKeyExA(root, subPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    char subKeyName[256];
    DWORD index = 0;

    while (true) {
        DWORD subKeySize = sizeof(subKeyName);
        LONG enumStatus = RegEnumKeyExA(
            hKey,
            index++,
            subKeyName,
            &subKeySize,
            nullptr,
            nullptr,
            nullptr,
            nullptr);

        if (enumStatus != ERROR_SUCCESS)
            break;

        HKEY hSubKey;
        if (RegOpenKeyExA(hKey, subKeyName, 0, KEY_READ, &hSubKey) != ERROR_SUCCESS)
            continue;

        ApplicationRecord app;
        if (!readStringValue(hSubKey, "DisplayName", app.name)) {
            RegCloseKey(hSubKey);
            continue;
        }

        app.type = "installed";
        app.scope = scope;
        app.user = user;

        readStringValue(hSubKey, "DisplayVersion", app.version);
        readStringValue(hSubKey, "Publisher", app.publisher);

        if (!readStringValue(hSubKey, "InstallLocation", app.installPath)) {
            // Fallback for entries that do not expose InstallLocation.
            readStringValue(hSubKey, "InstallSource", app.installPath);
        }

        app.source.type = "registry";
        app.source.location = makeRegistryPath(subPath, subKeyName);

        builder.addApplication(app);
        RegCloseKey(hSubKey);
    }

    RegCloseKey(hKey);
}

static void enumeratePerUserInstalled(JsonBuilder& builder) {
    HKEY hUsers;
    if (RegOpenKeyExA(HKEY_USERS, nullptr, 0, KEY_READ, &hUsers) != ERROR_SUCCESS)
        return;

    char sid[256];
    DWORD index = 0;

    while (true) {
        DWORD sidSize = sizeof(sid);
        LONG enumStatus = RegEnumKeyExA(
            hUsers,
            index++,
            sid,
            &sidSize,
            nullptr,
            nullptr,
            nullptr,
            nullptr);

        if (enumStatus != ERROR_SUCCESS)
            break;

        // Skip synthetic and classes branches.
        if (strncmp(sid, "S-1-5-", 6) != 0 || strstr(sid, "_Classes") != nullptr)
            continue;

        std::string user = sidToUsername(sid);
        if (user.empty())
            user = sid;

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
        "Machine",
        "SYSTEM",
        builder);

    readUninstallKey(
        HKEY_LOCAL_MACHINE,
        "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "Machine",
        "SYSTEM",
        builder);

    enumeratePerUserInstalled(builder);
}

void enumerateUwpPackages(JsonBuilder& builder) {
    constexpr const char* kUwpBasePath =
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx\\AppxAllUserStore\\Applications";

    HKEY hApplications;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, kUwpBasePath, 0, KEY_READ, &hApplications) != ERROR_SUCCESS)
        return;

    char subKeyName[512];
    DWORD index = 0;

    while (true) {
        DWORD subKeySize = sizeof(subKeyName);
        LONG enumStatus = RegEnumKeyExA(
            hApplications,
            index++,
            subKeyName,
            &subKeySize,
            nullptr,
            nullptr,
            nullptr,
            nullptr);

        if (enumStatus != ERROR_SUCCESS)
            break;

        HKEY hPackage;
        if (RegOpenKeyExA(hApplications, subKeyName, 0, KEY_READ, &hPackage) != ERROR_SUCCESS)
            continue;

        ApplicationRecord app;
        app.type = "uwp";
        app.scope = "Machine";
        app.user = "SYSTEM";
        app.name = subKeyName;

        // Keep package name deterministic; enrich when metadata exists.
        std::string value;
        if (readStringValue(hPackage, "DisplayName", value) && !value.empty())
            app.name = value;

        readStringValue(hPackage, "Version", app.version);

        if (!readStringValue(hPackage, "Publisher", app.publisher))
            readStringValue(hPackage, "PublisherDisplayName", app.publisher);

        if (!readStringValue(hPackage, "Path", app.installPath))
            readStringValue(hPackage, "PackageRootFolder", app.installPath);

        if (app.installPath.empty()) {
            // Best-effort canonical location when package path metadata is unavailable.
            app.installPath = std::string("C:\\Program Files\\WindowsApps\\") + subKeyName;
        }

        app.source.type = "registry";
        app.source.location = makeRegistryPath(kUwpBasePath, subKeyName);

        builder.addApplication(app);
        RegCloseKey(hPackage);
    }

    RegCloseKey(hApplications);
}
