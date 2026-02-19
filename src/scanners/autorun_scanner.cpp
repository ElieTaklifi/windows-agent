#include "autorun_scanner.h"

#include <stdexcept>
#include <set>

#ifdef _WIN32
#include <windows.h>
#include <string>
#include <sddl.h>    // ConvertStringSidToSidA
#include <lmcons.h>  // UNLEN

#pragma comment(lib, "advapi32.lib")

// ════════════════════════════════════════════════════════════════
//  Internal helpers — anonymous namespace, not exported.
//  Mirrors the structure of registry_scanner.cpp throughout.
// ════════════════════════════════════════════════════════════════
namespace {

// ── Registry read helpers ─────────────────────────────────────
// Identical signature and error-handling pattern to registry_scanner.cpp.
// Returns an empty string on any failure (absent value, wrong type,
// access denied); never throws.

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

// ── SID helpers ───────────────────────────────────────────────
// Identical to registry_scanner.cpp — kept local to this TU so
// both files remain self-contained without a shared utility header.

bool isSystemSid(const std::string& sid) {
    static const std::set<std::string> skip = {
        ".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20"
    };
    if (skip.count(sid)) return true;
    // Skip S-1-5-21-..._Classes virtual hives
    return sid.size() > 8 && sid.substr(sid.size() - 8) == "_Classes";
}

std::string sidToUsername(const char* sidStr) {
    PSID pSid = nullptr;
    if (!ConvertStringSidToSidA(sidStr, &pSid))
        return sidStr;

    char         name[UNLEN + 1] = {};
    char         domain[MAX_PATH] = {};
    DWORD        nameLen          = sizeof(name);
    DWORD        domainLen        = sizeof(domain);
    SID_NAME_USE use{};

    std::string result = sidStr;
    if (LookupAccountSidA(nullptr, pSid, name, &nameLen,
                          domain, &domainLen, &use))
        result = std::string(domain) + "\\" + name;

    LocalFree(pSid);
    return result;
}

// ── Entry construction ────────────────────────────────────────
// Builds a RawSoftwareEntry from a single autorun registry value.
// Populates rawMetadata in the same key/value schema used by
// enumerateUninstallRoot() in registry_scanner.cpp so the
// existing Normalizer and JsonExporter consume it without changes.
//
//   keyPath   → full subkey path (no HKLM/HKU root prefix)
//   valueName → value name inside that key
//   rawValue  → verbatim string data from the registry
//   context   → "machine" or "DOMAIN\username"
//   userSid   → raw SID string; empty for machine-wide entries
//   mechanism → one of the AutorunMechanism:: constants

RawSoftwareEntry makeAutorунEntry(
    const std::string& keyPath,
    const std::string& valueName,
    const std::string& rawValue,
    const std::string& context,
    const std::string& userSid,
    const char*        mechanism)
{
    RawSoftwareEntry entry;

    // name  — value name is the most meaningful label for autorun items
    // path  — the raw command line / DLL path stored in the value
    entry.name   = valueName.empty() ? rawValue : valueName;
    entry.path   = rawValue;
    entry.source = "persistence";

    // rawMetadata keys match the dashboard query-builder field names
    // and mirror the naming convention in registry_scanner.cpp
    entry.rawMetadata["mechanism"]    = mechanism;
    entry.rawMetadata["registryPath"] = keyPath;
    entry.rawMetadata["valueName"]    = valueName;
    entry.rawMetadata["rawValue"]     = rawValue;
    entry.rawMetadata["context"]      = context.empty() ? "machine" : context;

    if (!userSid.empty())
        entry.rawMetadata["userSid"] = userSid;

    return entry;
}

// ── Value enumerator ──────────────────────────────────────────
// Opens root\subPath and emits one RawSoftwareEntry per REG_SZ /
// REG_EXPAND_SZ value found.  Used for Run / RunOnce keys where
// every value is an independent autorun command.
// Silently returns if the key cannot be opened (absent or denied).

void enumerateRunKey(
    HKEY               root,
    const std::string& subPath,
    const char*        mechanism,
    const std::string& context,
    const std::string& userSid,
    std::vector<RawSoftwareEntry>& entries)
{
    HKEY key = nullptr;
    if (RegOpenKeyExA(root, subPath.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS)
        return;

    char  valueName[16384] = {};
    BYTE  valueData[32768] = {};

    for (DWORD idx = 0; ; ++idx) {
        DWORD nameSize = static_cast<DWORD>(sizeof(valueName));
        DWORD dataSize = static_cast<DWORD>(sizeof(valueData));
        DWORD type     = 0;

        LONG rc = RegEnumValueA(key, idx,
                                valueName, &nameSize,
                                nullptr, &type,
                                valueData, &dataSize);

        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS)       continue;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

        // Guarantee NUL termination before constructing std::string
        if (dataSize < sizeof(valueData))
            valueData[dataSize] = '\0';
        else
            valueData[sizeof(valueData) - 1] = '\0';

        std::string raw(reinterpret_cast<char*>(valueData));
        if (raw.empty()) continue;

        entries.push_back(makeAutorунEntry(
            subPath, valueName, raw, context, userSid, mechanism));
    }

    RegCloseKey(key);
}

// ── Named-value reader ────────────────────────────────────────
// Reads a single named value from root\subPath.  Used for Winlogon
// where only specific value names (Shell, Userinit…) are relevant.
// Emits no entry if the value is absent or empty.

void emitNamedValue(
    HKEY               root,
    const std::string& subPath,
    const char*        valueName,
    const char*        mechanism,
    const std::string& context,
    const std::string& userSid,
    std::vector<RawSoftwareEntry>& entries)
{
    HKEY key = nullptr;
    if (RegOpenKeyExA(root, subPath.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS)
        return;

    std::string raw = readRegString(key, valueName);
    RegCloseKey(key);

    if (raw.empty()) return;

    entries.push_back(makeAutorунEntry(
        subPath, valueName, raw, context, userSid, mechanism));
}

// ── Per-user HKU enumeration ──────────────────────────────────
// Iterates all SIDs loaded under HKEY_USERS, skips system accounts,
// and calls the provided callback for each real user SID.
// Same pattern as enumerateAllUsersHku() in registry_scanner.cpp.

template <typename Fn>
void forEachLoadedUser(Fn callback) {
    char sidBuf[256] = {};
    for (DWORD i = 0; ; ++i) {
        DWORD sidSize = sizeof(sidBuf);
        LONG  rc      = RegEnumKeyExA(HKEY_USERS, i, sidBuf, &sidSize,
                                      nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS)       continue;

        std::string sid(sidBuf);
        if (isSystemSid(sid)) continue;

        std::string userName = sidToUsername(sidBuf);
        callback(sid, userName);
    }
}

// ════════════════════════════════════════════════════════════════
//  Surface scanners
// ════════════════════════════════════════════════════════════════

// ── 1. Run / RunOnce / RunOnceEx ─────────────────────────────
//
//  Paths scanned:
//    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
//    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
//    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
//    HKLM\SOFTWARE\WOW6432Node\...\Run          (32-bit view)
//    HKLM\SOFTWARE\WOW6432Node\...\RunOnce      (32-bit view)
//    HKU\<SID>\SOFTWARE\...\Run                 (all loaded users)
//    HKU\<SID>\SOFTWARE\...\RunOnce             (all loaded users)
//
//  Each value under these keys is an independent autorun entry:
//    value name → entry.name / rawMetadata["valueName"]
//    value data → entry.path / rawMetadata["rawValue"]

void scanRunKeys(std::vector<RawSoftwareEntry>& entries) {
    // Machine-wide 64-bit
    const std::string base64 =
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\";
    enumerateRunKey(HKEY_LOCAL_MACHINE, base64 + "Run",
                    AutorunMechanism::RunKey, "machine", "", entries);
    enumerateRunKey(HKEY_LOCAL_MACHINE, base64 + "RunOnce",
                    AutorunMechanism::RunOnceKey, "machine", "", entries);
    enumerateRunKey(HKEY_LOCAL_MACHINE, base64 + "RunOnceEx",
                    AutorunMechanism::RunOnceKey, "machine", "", entries);

    // Machine-wide 32-bit (WOW64 node — separate view on 64-bit Windows)
    const std::string base32 =
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\";
    enumerateRunKey(HKEY_LOCAL_MACHINE, base32 + "Run",
                    AutorunMechanism::RunKey, "machine", "", entries);
    enumerateRunKey(HKEY_LOCAL_MACHINE, base32 + "RunOnce",
                    AutorunMechanism::RunOnceKey, "machine", "", entries);

    // Per-user — all SIDs currently loaded in HKU
    forEachLoadedUser([&](const std::string& sid, const std::string& userName) {
        const std::string userBase =
            sid + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\";
        enumerateRunKey(HKEY_USERS, userBase + "Run",
                        AutorunMechanism::RunKey, userName, sid, entries);
        enumerateRunKey(HKEY_USERS, userBase + "RunOnce",
                        AutorunMechanism::RunOnceKey, userName, sid, entries);
    });
}

// ── 2. Winlogon values ────────────────────────────────────────
//
//  Path: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
//
//  Values monitored:
//    Shell     → normally "explorer.exe"; replacement = system-level persistence
//    Userinit  → normally "C:\Windows\system32\userinit.exe,"; comma-suffix is valid
//    VmApplet  → points to system CPL DLL; rarely legitimately modified
//    AppSetup  → runs before user shell; almost never set on clean systems
//
//  Both HKLM and per-user HKU overrides are checked because Windows
//  merges user-hive Winlogon values with the machine hive at logon.
//  A per-user Shell override silently replaces explorer.exe for that user.

void scanWinlogon(std::vector<RawSoftwareEntry>& entries) {
    const std::string path =
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

    // Only these four values have execution semantics; others are config only
    static const char* kWatchedValues[] = {
        "Shell", "Userinit", "VmApplet", "AppSetup", nullptr
    };

    // Machine-wide values
    for (const char** v = kWatchedValues; *v; ++v) {
        emitNamedValue(HKEY_LOCAL_MACHINE, path, *v,
                       AutorunMechanism::WinlogonValue,
                       "machine", "", entries);
    }

    // Per-user overrides — a non-empty value here takes precedence over HKLM
    forEachLoadedUser([&](const std::string& sid, const std::string& userName) {
        const std::string userPath = sid + "\\" + path;
        for (const char** v = kWatchedValues; *v; ++v) {
            emitNamedValue(HKEY_USERS, userPath, *v,
                           AutorunMechanism::WinlogonValue,
                           userName, sid, entries);
        }
    });
}

}  // namespace
#endif  // _WIN32

// ════════════════════════════════════════════════════════════════
//  Public entry point
//  Matches the signature of RegistryScanner::scan() exactly.
// ════════════════════════════════════════════════════════════════
std::vector<RawSoftwareEntry> AutorunScanner::scan() {
    std::vector<RawSoftwareEntry> entries;

#ifdef _WIN32
    try {
        scanRunKeys(entries);   // Run / RunOnce / RunOnceEx
        scanWinlogon(entries);  // Winlogon Shell / Userinit / VmApplet / AppSetup

    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("AutorunScanner failed: ") + ex.what());
    }
#endif

    return entries;
}