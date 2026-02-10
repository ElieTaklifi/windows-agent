#pragma once
#include <string>
#include <vector>

struct ApplicationRecord {
    std::string scope;
    std::string user;
    std::string name;
    std::string version;
    std::string publisher;
    std::string installPath;
};

class JsonBuilder {
public:
    void addApplication(const ApplicationRecord& app);
    bool writeToFile(const std::string& filePath) const;

private:
    std::vector<ApplicationRecord> applications;
    static std::string escapeJson(const std::string& input);
};
