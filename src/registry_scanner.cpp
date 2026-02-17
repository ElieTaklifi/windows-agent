#include "registry_scanner.h"

#include <stdexcept>
#include <set>

#ifdef _WIN32
#include <windows.h>
#include <string>
#include <sddl.h>    // ConvertSidToStringSidA
#include <lmcons.h>  // UNLEN

#pragma comment(lib, "advapi32.lib")

namespace {

std::string readRegString(HKEY key, const char* name) {
    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExA(key, name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
        return {};
    if ((type != REG_SZ && type != REG_EXPAND_SZ) || size == 0)
        return {};

    std::string out(size, '\0');
    if (RegQueryValueExA(key, name, nullptr, nullptr,
                         reinterpret_cast<LPBYTE>(out.data()), &size) != ERROR_SUCCESS)
        return {};
    if (!out.empty() && out.back() == '\0')
        out.pop_back();
    return out;
}

// ─────────────────────────────────────────────────────────────
// Core enumeration: reads DisplayName + standard fields from
// every sub-key of root\path and appends to entries.
// contextUser: human-readable label injected into metadata
//              (empty string = "SYSTEM / machine-wide")
// ─────────────────────────────────────────────────────────────
void enumerateUninstallRoot(HKEY           root,
                             const std::string& path,
                             const std::string& contextUser,
                             std::vector<RawSoftwareEntry>& entries)
{
    HKEY uninstall = nullptr;
    // KEY_READ already requests the correct view via the key handle's flags;
    // callers that need WOW64 redirection should open with KEY_READ|KEY_WOW64_32KEY
    if (RegOpenKeyExA(root, path.c_str(), 0, KEY_READ, &uninstall) != ERROR_SUCCESS)
        return;

    char subkeyName[512] = {};
    for (DWORD index = 0; ; ++index) {
        DWORD subkeySize = static_cast<DWORD>(sizeof(subkeyName));
        LONG rc = RegEnumKeyExA(uninstall, index, subkeyName, &subkeySize,
                                nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS)       continue;

        HKEY subkey = nullptr;
        if (RegOpenKeyExA(uninstall, subkeyName, 0, KEY_READ, &subkey) != ERROR_SUCCESS)
            continue;

        RawSoftwareEntry entry;
        entry.name   = readRegString(subkey, "DisplayName");
        entry.path   = readRegString(subkey, "InstallLocation");
        entry.source = "registry";
        entry.rawMetadata["registryPath"]   = path + "\\" + subkeyName;
        entry.rawMetadata["publisher"]      = readRegString(subkey, "Publisher");
        entry.rawMetadata["displayVersion"] = readRegString(subkey, "DisplayVersion");
        entry.rawMetadata["installDate"]    = readRegString(subkey, "InstallDate");
        entry.rawMetadata["uninstallCmd"]   = readRegString(subkey, "UninstallString");
        entry.rawMetadata["estimatedSize"]  = readRegString(subkey, "EstimatedSize");
        entry.rawMetadata["language"]       = readRegString(subkey, "Language");
        entry.rawMetadata["context"]        = contextUser.empty() ? "machine" : contextUser;

        if (!entry.name.empty())
            entries.push_back(std::move(entry));

        RegCloseKey(subkey);
    }
    RegCloseKey(uninstall);
}

// ─────────────────────────────────────────────────────────────
// MSI UserData: HKLM\SOFTWARE\Microsoft\Windows\Installer\
//               UserData\<SID>\Products\<GUID>\InstallProperties
// This catches MSI packages that don't always appear in Uninstall.
// ─────────────────────────────────────────────────────────────
void enumerateMsiUserData(std::vector<RawSoftwareEntry>& entries) {
    const char* basePath =
        "SOFTWARE\\Microsoft\\Windows\\Installer\\UserData";

    HKEY base = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, basePath, 0, KEY_READ, &base) != ERROR_SUCCESS)
        return;

    char sidName[256] = {};
    for (DWORD si = 0; ; ++si) {
        DWORD sidSize = sizeof(sidName);
        if (RegEnumKeyExA(base, si, sidName, &sidSize,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;

        std::string productsPath = std::string(sidName) + "\\Products";
        HKEY products = nullptr;
        if (RegOpenKeyExA(base, productsPath.c_str(), 0, KEY_READ, &products) != ERROR_SUCCESS)
            continue;

        char productGuid[256] = {};
        for (DWORD pi = 0; ; ++pi) {
            DWORD guidSize = sizeof(productGuid);
            if (RegEnumKeyExA(products, pi, productGuid, &guidSize,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                break;

            std::string propPath = productsPath + "\\" + productGuid + "\\InstallProperties";
            HKEY prop = nullptr;
            if (RegOpenKeyExA(base, propPath.c_str(), 0, KEY_READ, &prop) != ERROR_SUCCESS)
                continue;

            RawSoftwareEntry entry;
            entry.name   = readRegString(prop, "DisplayName");
            entry.path   = readRegString(prop, "InstallLocation");
            entry.source = "registry-msi";
            entry.rawMetadata["registryPath"]   = std::string(basePath) + "\\" + propPath;
            entry.rawMetadata["publisher"]      = readRegString(prop, "Publisher");
            entry.rawMetadata["displayVersion"] = readRegString(prop, "DisplayVersion");
            entry.rawMetadata["installDate"]    = readRegString(prop, "InstallDate");
            entry.rawMetadata["msiProductCode"] = productGuid;
            entry.rawMetadata["userSid"]        = sidName;

            if (!entry.name.empty())
                entries.push_back(std::move(entry));

            RegCloseKey(prop);
        }
        RegCloseKey(products);
    }
    RegCloseKey(base);
}

// ─────────────────────────────────────────────────────────────
// Per-user scan via HKU.
// Iterates all SIDs loaded in the Users hive.  Skips well-known
// system SIDs (.DEFAULT, S-1-5-18/19/20).
// For offline users (hive not loaded) you would need RegLoadKey —
// see comment at the bottom of this file.
// ─────────────────────────────────────────────────────────────
bool isSystemSid(const std::string& sid) {
    // Skip .DEFAULT and built-in service accounts
    static const std::set<std::string> skip = {
        ".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20"
    };
    if (skip.count(sid)) return true;
    // Also skip _Classes sub-keys (e.g. S-1-5-21-..._Classes)
    return sid.size() > 8 && sid.substr(sid.size() - 8) == "_Classes";
}

void enumerateAllUsersHku(std::vector<RawSoftwareEntry>& entries) {
    // HKU is HKEY_USERS — no need to open it, it's a predefined root
    char sidName[256] = {};
    for (DWORD i = 0; ; ++i) {
        DWORD sidSize = sizeof(sidName);
        LONG rc = RegEnumKeyExA(HKEY_USERS, i, sidName, &sidSize,
                                nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS)       continue;

        std::string sid(sidName);
        if (isSystemSid(sid)) continue;

        // Resolve a friendly username from the SID for metadata
        std::string userName = sid;  // fallback
        {
            PSID pSid = nullptr;
            if (ConvertStringSidToSidA(sidName, &pSid)) {
                char name[UNLEN + 1]   = {};
                char domain[MAX_PATH]  = {};
                DWORD nameLen   = sizeof(name);
                DWORD domainLen = sizeof(domain);
                SID_NAME_USE use{};
                if (LookupAccountSidA(nullptr, pSid, name, &nameLen,
                                      domain, &domainLen, &use))
                    userName = std::string(domain) + "\\" + name;
                LocalFree(pSid);
            }
        }

        // 64-bit Uninstall under this user's hive
        enumerateUninstallRoot(
            HKEY_USERS,
            sid + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            userName, entries);

        // 32-bit Uninstall under this user's hive
        enumerateUninstallRoot(
            HKEY_USERS,
            sid + "\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            userName, entries);
    }
}

}  // namespace
#endif  // _WIN32

// ─────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────
std::vector<RawSoftwareEntry> RegistryScanner::scan() {
    std::vector<RawSoftwareEntry> entries;

#ifdef _WIN32
    try {
        // ── Machine-wide (64-bit view) ──────────────────────
        enumerateUninstallRoot(
            HKEY_LOCAL_MACHINE,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "", entries);

        // ── Machine-wide (32-bit view on 64-bit OS) ─────────
        enumerateUninstallRoot(
            HKEY_LOCAL_MACHINE,
            "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "", entries);

        // ── Per-user: all loaded user hives via HKU ──────────
        enumerateAllUsersHku(entries);

        // ── MSI UserData (catches MSI-only installs) ─────────
        enumerateMsiUserData(entries);

    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("RegistryScanner failed: ") + ex.what());
    }
#endif

    return entries;
}

/*
 ════════════════════════════════════════════════════════════════
  OFFLINE USER HIVES  (not implemented above — needs privileges)
 ════════════════════════════════════════════════════════════════
  Users who are NOT currently logged in won't have a hive loaded
  under HKU.  To scan them you must:

  1. Enable SeRestorePrivilege + SeBackupPrivilege on your process token.
  2. Enumerate C:\Users\* directories.
  3. For each directory whose SID is NOT already in HKU:
       RegLoadKeyA(HKEY_USERS, "TMP_<username>",
                   "C:\\Users\\<username>\\NTUSER.DAT");
  4. Run enumerateUninstallRoot / enumerateAllUsersHku on the
     temporary key.
  5. RegUnLoadKey(HKEY_USERS, "TMP_<username>") when done.

  This is intentionally left as a separate "offline hive loader"
  component since it requires elevated privileges and careful
  cleanup to avoid leaving hives loaded on failure.
 ════════════════════════════════════════════════════════════════
*/