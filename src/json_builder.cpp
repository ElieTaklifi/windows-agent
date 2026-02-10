#include "json_builder.h"
#include <fstream>

void JsonBuilder::addApplication(const ApplicationRecord& app) {
    applications.push_back(app);
}

std::string JsonBuilder::escapeJson(const std::string& input) {
    std::string output;
    for (char c : input) {
        switch (c) {
        case '\"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:   output += c; break;
        }
    }
    return output;
}

bool JsonBuilder::writeToFile(const std::string& filePath) const {
    std::ofstream file(filePath, std::ios::out | std::ios::trunc);
    if (!file.is_open())
        return false;

    file << "{\n  \"applications\": [\n";

    for (size_t i = 0; i < applications.size(); ++i) {
        const auto& app = applications[i];

        file << "    {\n";
        file << "      \"scope\": \"" << escapeJson(app.scope) << "\",\n";
        file << "      \"user\": \"" << escapeJson(app.user) << "\",\n";
        file << "      \"name\": \"" << escapeJson(app.name) << "\",\n";
        file << "      \"version\": \"" << escapeJson(app.version) << "\",\n";
        file << "      \"publisher\": \"" << escapeJson(app.publisher) << "\",\n";
        file << "      \"install_path\": \"" << escapeJson(app.installPath) << "\"\n";
        file << "    }";

        if (i + 1 < applications.size())
            file << ",";

        file << "\n";
    }

    file << "  ]\n}\n";
    file.close();
    return true;
}
