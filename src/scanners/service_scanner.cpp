#include "service_scanner.h"

#include <stdexcept>

#ifdef _WIN32
#include <windows.h>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

// ════════════════════════════════════════════════════════════════
//  Internal helpers — anonymous namespace, not exported.
//  Mirrors the structure of registry_scanner.cpp and
//  autorun_scanner.cpp throughout.
// ════════════════════════════════════════════════════════════════
namespace {

// ── Registry read helpers ─────────────────────────────────────
// Identical two-pass probe-then-read pattern used across every
// scanner in this codebase.  Returns empty string on any failure
// (absent value, wrong type, access denied); never throws.

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

// Read a REG_DWORD value.  Returns fallback on any failure.
DWORD readRegDword(HKEY key, const char* name, DWORD fallback = 0xFFFFFFFF) {
    DWORD value = 0;
    DWORD type  = 0;
    DWORD size  = sizeof(value);
    if (RegQueryValueExA(key, name, nullptr, &type,
                         reinterpret_cast<LPBYTE>(&value), &size) != ERROR_SUCCESS)
        return fallback;
    if (type != REG_DWORD)
        return fallback;
    return value;
}

// Read a REG_MULTI_SZ value and flatten all strings into a single
// semicolon-delimited string.  Returns empty on any failure.
// Used for RequiredPrivileges which is the only MULTI_SZ field we care about.
std::string readRegMultiSzFlat(HKEY key, const char* name) {
    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExA(key, name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
        return {};
    if (type != REG_MULTI_SZ || size == 0)
        return {};

    std::vector<char> buf(size, '\0');
    if (RegQueryValueExA(key, name, nullptr, nullptr,
                         reinterpret_cast<LPBYTE>(buf.data()), &size) != ERROR_SUCCESS)
        return {};

    // Walk the double-NUL-terminated list and join with semicolons
    std::string result;
    const char* p = buf.data();
    while (p < buf.data() + size && *p) {
        if (!result.empty()) result += ';';
        result += p;
        p += strlen(p) + 1;
    }
    return result;
}

// ── DWORD → human-readable string converters ──────────────────

// Service Type DWORD (winsvc.h).
// We mask off the interactive-process flag (0x100) before matching
// so SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS still maps
// to "OwnProcess" rather than falling through to the raw fallback.
std::string serviceTypeStr(DWORD type) {
    switch (type & ~static_cast<DWORD>(0x100)) {
        case SERVICE_KERNEL_DRIVER:       return ServiceType::KernelDriver;
        case SERVICE_FILE_SYSTEM_DRIVER:  return ServiceType::FilesystemDriver;
        case SERVICE_WIN32_OWN_PROCESS:   return ServiceType::OwnProcess;
        case SERVICE_WIN32_SHARE_PROCESS: return ServiceType::SharedProcess;
        default:
            // Return the raw decimal value so analysts can still look it up
            return std::to_string(static_cast<unsigned long>(type));
    }
}

// Start Type DWORD (winsvc.h).
std::string startTypeStr(DWORD start) {
    switch (start) {
        case SERVICE_BOOT_START:   return StartType::Boot;
        case SERVICE_SYSTEM_START: return StartType::System;
        case SERVICE_AUTO_START:   return StartType::Auto;
        case SERVICE_DEMAND_START: return StartType::Demand;
        case SERVICE_DISABLED:     return StartType::Disabled;
        default:                   return std::to_string(static_cast<unsigned long>(start));
    }
}

// Error Control DWORD (winsvc.h).
std::string errorControlStr(DWORD ec) {
    switch (ec) {
        case SERVICE_ERROR_IGNORE:   return "Ignore";
        case SERVICE_ERROR_NORMAL:   return "Normal";
        case SERVICE_ERROR_SEVERE:   return "Severe";
        case SERVICE_ERROR_CRITICAL: return "Critical";
        default:                     return std::to_string(static_cast<unsigned long>(ec));
    }
}

// ── FailureActions binary blob decoder ────────────────────────
// FailureActions is stored as REG_BINARY containing a serialised
// SERVICE_FAILURE_ACTIONS struct:
//
//   DWORD  dwResetPeriod   offset  0
//   DWORD  lpRebootMsg     offset  4  (pointer, meaningless in blob)
//   DWORD  lpCommand       offset  8  (pointer, meaningless in blob)
//   DWORD  cActions        offset 12
//   SC_ACTION actions[]    offset 16  each = { DWORD Type, DWORD Delay }
//
// We only need cActions and the first SC_ACTION.Type.
// The FailureCommand string is a separate REG_SZ value in the same key.

struct FailureInfo {
    std::string actionType;   // one of the FailureAction:: constants
    std::string command;      // populated only when actionType == "run_program"
};

FailureInfo readFailureActions(HKEY key) {
    FailureInfo info;
    info.actionType = FailureAction::None;

    BYTE  blob[1024] = {};
    DWORD blobSize   = sizeof(blob);
    DWORD type       = 0;

    if (RegQueryValueExA(key, "FailureActions", nullptr, &type,
                         blob, &blobSize) != ERROR_SUCCESS)
        return info;
    if (type != REG_BINARY || blobSize < 16)
        return info;

    // cActions is at byte offset 12
    DWORD cActions = 0;
    memcpy(&cActions, blob + 12, sizeof(DWORD));
    if (cActions == 0 || blobSize < 16 + 8)
        return info;   // need at least one full SC_ACTION (8 bytes)

    // First SC_ACTION.Type is at byte offset 16
    DWORD firstType = 0;
    memcpy(&firstType, blob + 16, sizeof(DWORD));

    switch (firstType) {
        case SC_ACTION_RESTART:     info.actionType = FailureAction::Restart;    break;
        case SC_ACTION_REBOOT:      info.actionType = FailureAction::Reboot;     break;
        case SC_ACTION_RUN_COMMAND: info.actionType = FailureAction::RunProgram; break;
        default:                    info.actionType = FailureAction::None;       break;
    }

    if (info.actionType == FailureAction::RunProgram)
        info.command = readRegString(key, "FailureCommand");

    return info;
}

// ── ImagePath resolver ────────────────────────────────────────
// Converts the raw ImagePath value — which may use any of three
// different path conventions — to a usable Win32 path so that
// GetFileAttributesEx can probe the binary.
//
// Convention 1: plain Win32 path, possibly with quotes and args
//   "C:\Windows\system32\svchost.exe -k netsvcs"
//
// Convention 2: \SystemRoot\ prefix (kernel convention)
//   \SystemRoot\System32\drivers\tcpip.sys
//
// Convention 3: \??\ native-namespace prefix
//   \??\C:\Windows\system32\drivers\null.sys
//
// After normalisation, ExpandEnvironmentStrings resolves any
// remaining %SystemRoot%, %SystemDrive% etc. tokens.

std::string resolveImagePath(const std::string& raw) {
    if (raw.empty()) return {};

    std::string path = raw;

    // Strip leading double-quote (services like svchost wrap only the
    // executable, not the whole command line, but some wrap everything)
    if (!path.empty() && path.front() == '"') {
        path.erase(0, 1);
        const auto q = path.find('"');
        if (q != std::string::npos)
            path.erase(q);   // keep only the executable token
    }

    // Strip any command-line arguments that follow a space after the .exe
    // so we probe the binary itself, not a mangled path with arguments.
    // We only do this when the path looks like it ends in .exe before args.
    const auto exePos = [&]() -> std::string::size_type {
        const std::string needle = ".exe";
        auto pos = std::string::npos;
        // Case-insensitive search: walk manually
        std::string lower = path;
        for (char& c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        pos = lower.rfind(needle);
        if (pos != std::string::npos)
            return pos + needle.size();
        return std::string::npos;
    }();
    if (exePos != std::string::npos && exePos < path.size())
        path.erase(exePos);   // trim everything after .exe

    // \SystemRoot\ → %SystemRoot%
    const std::string srPrefix = "\\SystemRoot\\";
    if (path.size() > srPrefix.size() &&
        _strnicmp(path.c_str(), srPrefix.c_str(), srPrefix.size()) == 0)
    {
        path = "%SystemRoot%\\" + path.substr(srPrefix.size());
    }

    // \??\ → strip prefix (gives a plain drive-letter path on most systems)
    const std::string nativePrefix = "\\??\\";
    if (path.size() > nativePrefix.size() &&
        path.substr(0, nativePrefix.size()) == nativePrefix)
    {
        path = path.substr(nativePrefix.size());
    }

    // Expand any remaining environment-variable tokens
    char expanded[MAX_PATH * 2] = {};
    if (ExpandEnvironmentStringsA(path.c_str(), expanded, sizeof(expanded)) > 0)
        return std::string(expanded);

    return path;
}

// ── File metadata probe ───────────────────────────────────────
// Uses GetFileAttributesEx to check existence, size, and last-write
// time without needing to open the file (works even when the binary
// is locked by the kernel).
// Returns empty strings for all fields if the file is absent or
// access is denied — the caller stores "false" for fileExists.

struct FileProbe {
    bool        exists           = false;
    std::string sizeBytes;        // decimal byte count
    std::string modifiedTimeUtc;  // ISO-8601 UTC, "YYYY-MM-DDTHH:MM:SSZ"
};

// Format a FILETIME as ISO-8601 UTC.
std::string filetimeToIso8601(const FILETIME& ft) {
    SYSTEMTIME st = {};
    if (!FileTimeToSystemTime(&ft, &st)) return {};
    char buf[32] = {};
    snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02uZ",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
    return buf;
}

FileProbe probeFile(const std::string& win32Path) {
    FileProbe fp;
    if (win32Path.empty()) return fp;

    WIN32_FILE_ATTRIBUTE_DATA attr = {};
    if (!GetFileAttributesExA(win32Path.c_str(), GetFileExInfoStandard, &attr))
        return fp;   // absent or access denied

    fp.exists = true;

    ULARGE_INTEGER sz;
    sz.LowPart  = attr.nFileSizeLow;
    sz.HighPart = attr.nFileSizeHigh;
    fp.sizeBytes = std::to_string(sz.QuadPart);

    fp.modifiedTimeUtc = filetimeToIso8601(attr.ftLastWriteTime);
    return fp;
}

// ════════════════════════════════════════════════════════════════
//  Core enumerator
//  Opens HKLM\SYSTEM\CurrentControlSet\Services and iterates
//  every subkey.  Each subkey is one service or driver record.
// ════════════════════════════════════════════════════════════════

// Registry path for the Services hive — no leading backslash,
// no HKLM prefix (that is implicit in the RegOpenKeyExA call).
static const char* kServicesPath = "SYSTEM\\CurrentControlSet\\Services";

void enumerateServices(std::vector<RawSoftwareEntry>& entries) {

    HKEY base = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, kServicesPath, 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS, &base) != ERROR_SUCCESS)
        return;

    char subkeyBuf[256] = {};
    for (DWORD index = 0; ; ++index) {
        DWORD subkeySize = static_cast<DWORD>(sizeof(subkeyBuf));
        const LONG rc = RegEnumKeyExA(base, index, subkeyBuf, &subkeySize,
                                      nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS)       continue;

        HKEY sub = nullptr;
        if (RegOpenKeyExA(base, subkeyBuf, 0, KEY_READ, &sub) != ERROR_SUCCESS)
            continue;

        // ── Read all values for this service subkey ────────────

        const DWORD rawType   = readRegDword(sub, "Type",         0);
        const DWORD rawStart  = readRegDword(sub, "Start",        SERVICE_DEMAND_START);
        const DWORD rawError  = readRegDword(sub, "ErrorControl", SERVICE_ERROR_NORMAL);
        const DWORD rawSidType= readRegDword(sub, "ServiceSidType",0);
        const DWORD rawTag    = readRegDword(sub, "Tag",           0);

        const std::string imagePath    = readRegString(sub, "ImagePath");
        const std::string displayName  = readRegString(sub, "DisplayName");
        const std::string description  = readRegString(sub, "Description");
        const std::string objectName   = readRegString(sub, "ObjectName");
        const std::string group        = readRegString(sub, "Group");
        const std::string requiredPrivs= readRegMultiSzFlat(sub, "RequiredPrivileges");

        const FailureInfo failure = readFailureActions(sub);

        RegCloseKey(sub);

        // ── Filter: skip pure device / adapter entries ─────────
        // Type 4 = Adapter, Type 8 = Recognizer — these have no
        // ImagePath and represent hardware, not executable surfaces.
        const bool isDriver  = (rawType == SERVICE_KERNEL_DRIVER ||
                                rawType == SERVICE_FILE_SYSTEM_DRIVER);
        const bool isService = ((rawType & SERVICE_WIN32_OWN_PROCESS)  != 0 ||
                                (rawType & SERVICE_WIN32_SHARE_PROCESS) != 0);

        if (!isDriver && !isService && imagePath.empty())
            continue;

        // ── Resolve and probe the binary ───────────────────────
        const std::string resolvedPath = resolveImagePath(imagePath);
        const FileProbe   fp           = probeFile(resolvedPath);

        // ── Build the RawSoftwareEntry ─────────────────────────
        RawSoftwareEntry entry;

        // Prefer DisplayName (human readable); fall back to the
        // subkey name which is the SCM canonical service name.
        entry.name   = displayName.empty() ? subkeyBuf : displayName;
        entry.path   = resolvedPath;
        entry.source = "service";

        // ── rawMetadata — one key per scanner field ────────────
        // Keys match the field names documented in the header and
        // expected by the normalizer / dashboard query builder.

        entry.rawMetadata["registryPath"]     = std::string(kServicesPath) + "\\" + subkeyBuf;
        entry.rawMetadata["serviceName"]      = subkeyBuf;
        entry.rawMetadata["displayName"]      = displayName;
        entry.rawMetadata["description"]      = description;
        entry.rawMetadata["imagePath"]        = imagePath;
        entry.rawMetadata["resolvedPath"]     = resolvedPath;
        entry.rawMetadata["objectName"]       = objectName;
        entry.rawMetadata["startType"]        = startTypeStr(rawStart);
        entry.rawMetadata["serviceType"]      = serviceTypeStr(
            
        );
        entry.rawMetadata["errorControl"]     = errorControlStr(rawError);
        entry.rawMetadata["group"]            = group;
        entry.rawMetadata["tag"]              = (rawTag != 0)
                                                ? std::to_string(static_cast<unsigned long>(rawTag))
                                                : "";
        entry.rawMetadata["failureActions"]   = failure.actionType;
        entry.rawMetadata["failureCommand"]   = failure.command;
        entry.rawMetadata["requiredPrivs"]    = requiredPrivs;
        entry.rawMetadata["sidType"]          = std::to_string(
                                                    static_cast<unsigned long>(rawSidType));
        entry.rawMetadata["fileExists"]       = fp.exists ? "true" : "false";
        entry.rawMetadata["fileSizeBytes"]    = fp.sizeBytes;
        entry.rawMetadata["fileModifiedTime"] = fp.modifiedTimeUtc;

        entries.push_back(std::move(entry));
    }

    RegCloseKey(base);
}

}  // namespace
#endif  // _WIN32

// ════════════════════════════════════════════════════════════════
//  Public entry point
//  Matches RegistryScanner::scan() and AutorunScanner::scan()
//  signature exactly — no arguments, returns by value.
// ════════════════════════════════════════════════════════════════
std::vector<RawSoftwareEntry> ServiceScanner::scan() {
    std::vector<RawSoftwareEntry> entries;

#ifdef _WIN32
    try {
        enumerateServices(entries);
    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("ServiceScanner failed: ") + ex.what());
    }
#endif

    return entries;
}