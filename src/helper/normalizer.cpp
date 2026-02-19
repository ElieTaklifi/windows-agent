#include "normalizer.h"

namespace {

std::string inferType(const RawSoftwareEntry& raw) {
    if (raw.source == "os_catalog") {
        return "UWP";
    }
    if (raw.source == "registry") {
        return "Win32";
    }
    if (raw.source == "persistence") {
        return "Service";
    }
    return "Portable";
}

std::string inferScope(const RawSoftwareEntry& raw) {
    const auto it = raw.rawMetadata.find("registryPath");
    if (it != raw.rawMetadata.end() && it->second.find("HKEY_CURRENT_USER") != std::string::npos) {
        return "per-user";
    }
    return "per-machine";
}

std::string inferExplanation(const RawSoftwareEntry& raw) {
    if (raw.source == "registry") {
        return "Found in uninstall registry keys; indicates installed software with standard registration and likely regular execution footprint.";
    }
    if (raw.source == "registry-msi") {
        return "Found in MSI UserData registry records; confirms Windows Installer-managed software and potential machine-wide impact.";
    }
    if (raw.source == "os_catalog") {
        return "Found in Windows AppX catalog; indicates packaged UWP app presence that can execute in user context.";
    }
    if (raw.source == "filesystem") {
        return "Found by executable file scan in Program Files paths; may indicate manually deployed or portable software that can run directly.";
    }
    if (raw.source == "persistence") {
        const auto mechanismIt = raw.rawMetadata.find("mechanism");
        if (mechanismIt != raw.rawMetadata.end() && !mechanismIt->second.empty()) {
            return "Found in persistence surface (" + mechanismIt->second + "); can auto-start and maintain recurring execution on this host.";
        }
        return "Found in persistence surface; can auto-start and maintain recurring execution on this host.";
    }
    return "Found by telemetry scanner source " + raw.source + "; indicates executable presence that may affect host attack surface.";
}

}  // namespace

NormalizedSoftwareEntry Normalizer::normalize(const RawSoftwareEntry& raw) const {
    NormalizedSoftwareEntry normalized;
    normalized.name = raw.name;
    normalized.type = inferType(raw);
    normalized.scope = inferScope(raw);
    normalized.source = raw.source;
    normalized.explanation = inferExplanation(raw);
    normalized.userSID = "N/A";
    normalized.metadata = raw.rawMetadata;
    normalized.metadata["path"] = raw.path;
    return normalized;
}

std::vector<NormalizedSoftwareEntry> Normalizer::normalizeAll(const std::vector<RawSoftwareEntry>& rawEntries) const {
    std::vector<NormalizedSoftwareEntry> output;
    output.reserve(rawEntries.size());

    for (const auto& entry : rawEntries) {
        output.push_back(normalize(entry));
    }

    return output;
}
