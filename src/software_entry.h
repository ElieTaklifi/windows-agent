#pragma once

#include <map>
#include <string>

struct RawSoftwareEntry {
    std::string name;
    std::string path;
    std::string source;
    std::map<std::string, std::string> rawMetadata;
};

struct NormalizedSoftwareEntry {
    std::string name;
    std::string type;
    std::string scope;
    std::string source;
    std::string explanation;
    std::string userSID;
    std::string severity;        // "critical" | "high" | "medium" | "low"
    std::string severityReasons; // semicolon-delimited human-readable reason list
    std::map<std::string, std::string> metadata;
};