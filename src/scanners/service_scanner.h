#pragma once

// ════════════════════════════════════════════════════════════════
//  service_scanner.h
//
//  Discovers all Windows services and kernel / filesystem drivers
//  registered under:
//
//    HKLM\SYSTEM\CurrentControlSet\Services\*
//
//  Every subkey is one service or driver record.  The scanner
//  reads every security-relevant registry value, resolves the
//  binary path on disk, and probes the file so downstream
//  consumers (normalizer, dashboard) can correlate registry
//  state with filesystem reality without a second pass.
//
//  ── Output schema ─────────────────────────────────────────────
//    entry.name                  → DisplayName if present, else subkey name
//    entry.path                  → resolved Win32 binary path
//    entry.source                → "service"
//
//    entry.rawMetadata fields:
//      "registryPath"            → full subkey path under Services\
//      "serviceName"             → subkey name (SCM canonical identifier)
//      "displayName"             → DisplayName value (human label)
//      "description"             → Description value
//      "imagePath"               → ImagePath verbatim from registry
//      "resolvedPath"            → Win32 path after environment expansion
//                                  and native-path prefix stripping
//      "objectName"              → account the service runs as
//                                  (e.g. "LocalSystem", "NT AUTHORITY\NetworkService")
//      "startType"               → "Boot" | "System" | "Auto" | "Demand" | "Disabled"
//      "serviceType"             → "KernelDriver" | "FilesystemDriver" |
//                                  "OwnProcess"   | "SharedProcess"    | <raw DWORD>
//      "errorControl"            → "Ignore" | "Normal" | "Severe" | "Critical"
//      "group"                   → load-order group name (drivers)
//      "tag"                     → decimal tag value within group (drivers, "" if 0)
//      "failureActions"          → first failure action type:
//                                  "restart" | "reboot" | "run_program" | "none"
//      "failureCommand"          → binary executed on failure when action==run_program
//      "requiredPrivs"           → semicolon-separated privilege list
//                                  (from REG_MULTI_SZ RequiredPrivileges)
//      "sidType"                 → decimal ServiceSidType DWORD
//      "fileExists"              → "true" | "false"
//      "fileSizeBytes"           → decimal byte count, "" if file absent / inaccessible
//      "fileModifiedTime"        → ISO-8601 UTC last-write time, "" if unavailable
//
//  ── Normalizer integration ────────────────────────────────────
//  The normalizer dispatches on source == "service" and reads
//  rawMetadata["serviceType"] to produce:
//    KernelDriver / FilesystemDriver  → type = "Driver"
//    SharedProcess                    → type = "SharedService"
//    anything else                    → type = "Service"
//  Scope is always "per-machine" for this source.
//  No changes to JsonExporter are required.
// ════════════════════════════════════════════════════════════════

#include "idiscovery_scanner.h"

// String constants written into rawMetadata["serviceType"].
// Used by the normalizer and dashboard without re-parsing DWORDs.
namespace ServiceType {
    constexpr const char* KernelDriver      = "KernelDriver";
    constexpr const char* FilesystemDriver  = "FilesystemDriver";
    constexpr const char* OwnProcess        = "OwnProcess";
    constexpr const char* SharedProcess     = "SharedProcess";
}

// String constants written into rawMetadata["startType"].
namespace StartType {
    constexpr const char* Boot     = "Boot";
    constexpr const char* System   = "System";
    constexpr const char* Auto     = "Auto";
    constexpr const char* Demand   = "Demand";
    constexpr const char* Disabled = "Disabled";
}

// String constants written into rawMetadata["failureActions"].
namespace FailureAction {
    constexpr const char* Restart    = "restart";
    constexpr const char* Reboot     = "reboot";
    constexpr const char* RunProgram = "run_program";
    constexpr const char* None       = "none";
}

class ServiceScanner final : public IDiscoveryScanner {
public:
    std::vector<RawSoftwareEntry> scan() override;
};