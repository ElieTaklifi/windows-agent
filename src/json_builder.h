#pragma once
#include <string>
#include <map>
#include <vector>

struct DetectionSource {
    std::string type;      // registry | filesystem | task | service | msi | uwp
    std::string location;  // exact registry path, directory, task name, etc.
};

struct ApplicationRecord {
    std::string type;        // portable | installed | uwp | driver | service | task | msi_hidden
    std::string scope;       // Machine | PerUser | Observed | SYSTEM
    std::string user;        // Username or SYSTEM
    std::string name;
    std::string version;
    std::string publisher;
    std::string installPath;

    DetectionSource source;
};

class JsonBuilder {
public:
    void addApplication(const ApplicationRecord& app);
    bool writeToFile(const std::string& filePath) const;

private:
    std::string escapeJson(const std::string& input) const;

    using AppList = std::vector<ApplicationRecord>;
    using UserMap = std::map<std::string, AppList>;
    using ScopeMap = std::map<std::string, UserMap>;
    using TypeMap  = std::map<std::string, ScopeMap>;

    TypeMap apps;
};
