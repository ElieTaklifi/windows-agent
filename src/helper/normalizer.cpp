#include "normalizer.h"

#include <algorithm>
#include <vector>

// ════════════════════════════════════════════════════════════════
//  normalizer.cpp
//
//  Maps RawSoftwareEntry → NormalizedSoftwareEntry.
//  Computes severity (critical|high|medium|low) and a list of
//  human-readable reasons for every entry.
//
//  Severity model per source:
//    registry / registry-msi  → path, publisher, version signals
//    persistence              → mechanism + context + path
//    service                  → type, account, start, binary presence
//    filesystem               → path location heuristics
//    os_catalog               → sandbox status, sideload detection
// ════════════════════════════════════════════════════════════════

namespace {

// ── Small helpers ─────────────────────────────────────────────

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

bool containsAny(const std::string& haystack,
                 std::initializer_list<const char*> needles) {
    std::string h = toLower(haystack);
    for (const char* n : needles)
        if (h.find(n) != std::string::npos) return true;
    return false;
}

std::string getmeta(const std::map<std::string, std::string>& m,
                    const char* key) {
    auto it = m.find(key);
    return it != m.end() ? it->second : "";
}

// ── SeverityResult ────────────────────────────────────────────

struct SR {
    int                      rank = 0;   // 0=low 1=medium 2=high 3=critical
    std::vector<std::string> reasons;

    void bump(int r, std::string reason) {
        if (r > rank) rank = r;
        reasons.push_back(std::move(reason));
    }
    std::string level() const {
        switch (rank) {
            case 3: return "critical";
            case 2: return "high";
            case 1: return "medium";
            default: return "low";
        }
    }
    std::string joinReasons() const {
        std::string out;
        for (size_t i = 0; i < reasons.size(); ++i) {
            if (i) out += "; ";
            out += reasons[i];
        }
        return out;
    }
};

// ── Type inference ────────────────────────────────────────────

std::string inferType(const RawSoftwareEntry& raw) {
    if (raw.source == "os_catalog")   return "UWP";
    if (raw.source == "registry")     return "Win32";
    if (raw.source == "registry-msi") return "Win32";
    if (raw.source == "persistence")  return "Service";
    if (raw.source == "filesystem")   return "Portable";
    if (raw.source == "service") {
        auto it = raw.rawMetadata.find("serviceType");
        if (it != raw.rawMetadata.end()) {
            if (it->second == "KernelDriver" || it->second == "FilesystemDriver")
                return "Driver";
            if (it->second == "SharedProcess")
                return "SharedService";
        }
        return "Service";
    }
    return "Portable";
}

// ── Scope inference ───────────────────────────────────────────

std::string inferScope(const RawSoftwareEntry& raw) {
    if (raw.source == "service") return "per-machine";
    if (raw.source == "persistence") {
        auto it = raw.rawMetadata.find("context");
        if (it != raw.rawMetadata.end() && it->second != "machine")
            return "per-user";
        return "per-machine";
    }
    auto it = raw.rawMetadata.find("registryPath");
    if (it != raw.rawMetadata.end()) {
        const std::string& rp = it->second;
        if (rp.find("HKEY_CURRENT_USER") != std::string::npos ||
            rp.find("HKU\\") != std::string::npos)
            return "per-user";
    }
    return "per-machine";
}

std::string inferUserSid(const RawSoftwareEntry& raw) {
    auto it = raw.rawMetadata.find("userSid");
    if (it != raw.rawMetadata.end() && !it->second.empty())
        return it->second;
    return "N/A";
}

std::string inferExplanation(const RawSoftwareEntry& raw) {
    if (raw.source == "registry")
        return "Found in uninstall registry keys; indicates installed software "
               "with standard registration and likely regular execution footprint.";
    if (raw.source == "registry-msi")
        return "Found in MSI UserData registry records; confirms Windows Installer-"
               "managed software and potential machine-wide impact.";
    if (raw.source == "os_catalog")
        return "Found in Windows AppX catalog; indicates packaged UWP app presence "
               "that can execute in user context.";
    if (raw.source == "filesystem")
        return "Found by executable file scan in Program Files paths; may indicate "
               "manually deployed or portable software that can run directly.";
    if (raw.source == "persistence") {
        std::string mech = getmeta(raw.rawMetadata, "mechanism");
        if (!mech.empty())
            return "Found in persistence surface (" + mech +
                   "); can auto-start and maintain recurring execution on this host.";
        return "Found in persistence surface; can auto-start and maintain "
               "recurring execution on this host.";
    }
    if (raw.source == "service") {
        std::string t = getmeta(raw.rawMetadata, "serviceType");
        if (t == "KernelDriver" || t == "FilesystemDriver")
            return "Kernel/filesystem driver registered in SCM; runs in ring-0 "
                   "with full hardware access, no OS memory protection.";
        return "Windows service registered in SCM; runs at boot or on-demand, "
               "potentially as SYSTEM or a privileged account.";
    }
    return "Found by scanner source " + raw.source +
           "; indicates executable presence that may affect host attack surface.";
}

// ════════════════════════════════════════════════════════════════
//  Per-source severity calculators
// ════════════════════════════════════════════════════════════════

// ── Registry / MSI ───────────────────────────────────────────
//  Key signals: missing publisher, missing version, TEMP path,
//  no install date, per-user install without publisher.

SR severityRegistry(const RawSoftwareEntry& raw) {
    SR r;
    std::string publisher = getmeta(raw.rawMetadata, "publisher");
    std::string version   = getmeta(raw.rawMetadata, "displayVersion");
    std::string date      = getmeta(raw.rawMetadata, "installDate");
    std::string path      = toLower(raw.path.empty()
                                ? getmeta(raw.rawMetadata, "path") : raw.path);
    std::string scope     = inferScope(raw);

    if (containsAny(path, {"\\temp\\", "\\tmp\\", "/temp/", "/tmp/"}))
        r.bump(2, "Binary installed to TEMP directory — strong indicator of dropper activity");

    if (publisher.empty())
        r.bump(1, "No publisher recorded — cannot verify software origin");

    if (version.empty())
        r.bump(1, "No version string — unusual for legitimate installers");

    if (date.empty())
        r.bump(1, "No install date — may indicate manual registry write rather than installer");

    if (scope == "per-user" && publisher.empty())
        r.bump(1, "Per-user install with no publisher — elevated suspicion");

    if (r.reasons.empty())
        r.reasons.push_back("Standard installer registration with publisher, version, and date");

    return r;
}

// ── Persistence / Autorun ────────────────────────────────────
//  Key signals: mechanism type, machine vs user scope, binary path.

SR severityPersistence(const RawSoftwareEntry& raw) {
    SR r;
    std::string mech    = getmeta(raw.rawMetadata, "mechanism");
    std::string context = getmeta(raw.rawMetadata, "context");
    std::string path    = toLower(raw.path.empty()
                              ? getmeta(raw.rawMetadata, "rawValue") : raw.path);

    // Winlogon — runs as SYSTEM before user shell
    if (mech == "winlogon_value") {
        // Check if it's just the normal Windows value
        if (containsAny(path, {"explorer.exe", "userinit.exe"})) {
            r.bump(0, "Winlogon value present but points to standard Windows binary — expected");
        } else {
            r.bump(3, "Winlogon value override — executes as SYSTEM before user shell loads");
        }
        return r;
    }

    // HKLM Run — machine-wide, all users
    if ((mech == "run_key" || mech == "run_once_key") && context == "machine")
        r.bump(2, "HKLM Run key — executes for all users at every logon");

    // HKCU / per-user Run
    if ((mech == "run_key" || mech == "run_once_key") && context != "machine")
        r.bump(1, "HKU Run key — executes at logon for a specific user");

    if (mech == "startup_folder")
        r.bump(1, "Startup folder — executes on logon");

    // Path modifiers
    if (containsAny(path, {"\\temp\\", "\\tmp\\", "%temp%", "\\appdata\\local\\temp\\"})) {
        r.bump(3, "Persistence target in TEMP/AppData Temp — strong malware indicator");
    } else if (containsAny(path, {"\\appdata\\roaming\\", "\\appdata\\local\\"})) {
        r.bump(2, "Persistence target in AppData — common malware install path");
    } else if (containsAny(path, {"\\windows\\system32\\", "\\windows\\syswow64\\",
                                   "c:\\program files\\", "c:\\program files (x86)\\"})) {
        // Trusted path — reduce rank by 1
        if (r.rank > 0) {
            r.rank--;
            r.reasons.push_back("Path within trusted system/program directory — reduces suspicion");
        }
    }

    if (r.reasons.empty())
        r.reasons.push_back("Persistence mechanism registered — verify binary is expected");

    return r;
}

// ── Services / Drivers ───────────────────────────────────────
//  Key signals: kernel driver, missing binary, SYSTEM account,
//  boot/system start, failure run_program, suspicious path.

SR severityService(const RawSoftwareEntry& raw) {
    SR r;
    std::string svcType    = getmeta(raw.rawMetadata, "serviceType");
    std::string startType  = getmeta(raw.rawMetadata, "startType");
    std::string account    = toLower(getmeta(raw.rawMetadata, "objectName"));
    std::string path       = toLower(getmeta(raw.rawMetadata, "resolvedPath"));
    std::string fileExists = getmeta(raw.rawMetadata, "fileExists");
    std::string failure    = getmeta(raw.rawMetadata, "failureActions");
    std::string failCmd    = getmeta(raw.rawMetadata, "failureCommand");

    if (svcType == "KernelDriver" || svcType == "FilesystemDriver")
        r.bump(2, "Kernel/filesystem driver — ring-0 execution, no memory protection");

    if (fileExists == "false" && !path.empty())
        r.bump(3, "Registered binary missing from disk — entry orphaned or binary deleted post-install");

    if (account.empty() || account == "localsystem" ||
        account.find("localsystem") != std::string::npos)
        r.bump(1, "Runs as LocalSystem — highest privilege level on the machine");

    if (startType == "Boot" || startType == "System")
        r.bump(1, "Start type Boot/System — loads before user space and before AV initialises");

    if (startType == "Auto" && r.rank == 0)
        r.bump(1, "Auto-start service — persistent background execution");

    if (failure == "run_program")
        r.bump(2, "Failure action executes binary on crash: " +
                  (failCmd.empty() ? "(unspecified)" : failCmd));

    if (containsAny(path, {"\\temp\\", "\\tmp\\", "%temp%"}))
        r.bump(3, "Service binary in TEMP directory — immediate investigation required");

    if (r.reasons.empty())
        r.reasons.push_back("Demand-start service with standard configuration — low risk baseline");

    return r;
}

// ── Filesystem executables ───────────────────────────────────
//  Key signals: path location, double extension.

SR severityFilesystem(const RawSoftwareEntry& raw) {
    SR r;
    std::string path = toLower(raw.path);
    std::string name = toLower(raw.name);

    if (containsAny(path, {"\\temp\\", "\\tmp\\", "%temp%", "\\appdata\\local\\temp\\"}))
        r.bump(3, "Executable in TEMP — classic dropper/stager location");
    else if (containsAny(path, {"\\appdata\\roaming\\", "\\appdata\\local\\"}))
        r.bump(2, "Executable in AppData — common malware install path");
    else if (path.find("\\program files\\") != std::string::npos ||
             path.find("\\program files (x86)\\") != std::string::npos)
        r.bump(0, "Executable in Program Files — standard install location");
    else
        r.bump(1, "Executable outside standard install paths — verify origin");

    if (containsAny(name, {".pdf.exe",".doc.exe",".txt.exe",".jpg.exe",".xls.exe"}))
        r.bump(3, "Double extension detected — masquerading as document file");

    return r;
}

// ── AppX / UWP catalog ───────────────────────────────────────

SR severityOsCatalog(const RawSoftwareEntry& raw) {
    SR r;
    std::string path = toLower(raw.path);
    if (!path.empty() && path.find("windowsapps") == std::string::npos) {
        r.bump(1, "AppX package installed outside WindowsApps — possible sideloaded package");
    } else {
        r.bump(0, "Packaged UWP app in WindowsApps — sandboxed execution with declared capabilities");
    }
    return r;
}

// ── Dispatcher ───────────────────────────────────────────────

SR computeSeverity(const RawSoftwareEntry& raw) {
    if (raw.source == "registry" || raw.source == "registry-msi")
        return severityRegistry(raw);
    if (raw.source == "persistence")
        return severityPersistence(raw);
    if (raw.source == "service")
        return severityService(raw);
    if (raw.source == "filesystem")
        return severityFilesystem(raw);
    if (raw.source == "os_catalog")
        return severityOsCatalog(raw);

    SR r;
    r.bump(0, "Unknown source — insufficient data for severity scoring");
    return r;
}

}  // namespace

// ════════════════════════════════════════════════════════════════
//  Public interface
// ════════════════════════════════════════════════════════════════

NormalizedSoftwareEntry Normalizer::normalize(const RawSoftwareEntry& raw) const {
    NormalizedSoftwareEntry n;
    n.name        = raw.name;
    n.type        = inferType(raw);
    n.scope       = inferScope(raw);
    n.source      = raw.source;
    n.explanation = inferExplanation(raw);
    n.userSID     = inferUserSid(raw);
    n.metadata    = raw.rawMetadata;
    n.metadata["path"] = raw.path;

    SR sev = computeSeverity(raw);
    n.severity        = sev.level();
    n.severityReasons = sev.joinReasons();

    // Also store in metadata so the JSON/dashboard can access them uniformly
    n.metadata["severity"]        = n.severity;
    n.metadata["severityReasons"] = n.severityReasons;

    return n;
}

std::vector<NormalizedSoftwareEntry> Normalizer::normalizeAll(
    const std::vector<RawSoftwareEntry>& rawEntries) const
{
    std::vector<NormalizedSoftwareEntry> output;
    output.reserve(rawEntries.size());
    for (const auto& e : rawEntries)
        output.push_back(normalize(e));
    return output;
}
