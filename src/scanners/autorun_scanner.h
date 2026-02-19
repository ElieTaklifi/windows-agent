#pragma once

// ════════════════════════════════════════════════════════════════
//  autorun_scanner.h
//
//  Discovers registry-based persistence entries for:
//    1. Run / RunOnce / RunOnceEx keys
//       HKLM (64-bit and WOW64) + all loaded HKU hives
//    2. Winlogon values (Shell, Userinit, VmApplet, AppSetup)
//       HKLM + per-user HKU overrides
//
//  Output schema (mirrors RegistryScanner entries):
//    entry.name                → value name inside the registry key
//    entry.path                → raw command / DLL string from the value
//    entry.source              → "persistence"
//    entry.rawMetadata fields:
//        "mechanism"           → see AutorunMechanism:: constants
//        "registryPath"        → full key path (no root prefix)
//        "valueName"           → registry value name
//        "rawValue"            → verbatim string read from the registry
//        "context"             → "machine" | "<DOMAIN>\<username>"
//        "userSid"             → SID string (per-user entries only)
//
//  The normalizer maps source=="persistence" → type="Service" and
//  infers scope from "context" in rawMetadata, so no changes to
//  the normalizer or exporter are needed to consume this scanner.
// ════════════════════════════════════════════════════════════════

#include "idiscovery_scanner.h"

// Mechanism tag constants written into rawMetadata["mechanism"].
// Callers (normalizer, dashboard) can filter/risk-score on these
// without re-parsing paths or key names.
namespace AutorunMechanism {
    constexpr const char* RunKey        = "run_key";
    constexpr const char* RunOnceKey    = "run_once_key";
    constexpr const char* WinlogonValue = "winlogon_value";
}

class AutorunScanner final : public IDiscoveryScanner {
public:
    std::vector<RawSoftwareEntry> scan() override;
};