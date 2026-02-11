#include "json_builder.h"
#include <fstream>

void JsonBuilder::addApplication(const ApplicationRecord& app) {
    apps[app.type][app.scope][app.user].push_back(app);
}

std::string JsonBuilder::escapeJson(const std::string& input) const {
    std::string output;
    output.reserve(input.size());

    for (char c : input) {
        switch (c) {
        case '\"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\n': output += "\\n";  break;
        case '\r': output += "\\r";  break;
        case '\t': output += "\\t";  break;
        default:   output += c;      break;
        }
    }
    return output;
}

bool JsonBuilder::writeToFile(const std::string& filePath) const {
    std::ofstream file(filePath, std::ios::out | std::ios::trunc);
    if (!file.is_open())
        return false;

    file << "{\n  \"app\": {\n";

    bool firstType = true;
    for (const auto& [type, scopes] : apps) {
        if (!firstType) file << ",\n";
        firstType = false;

        file << "    \"" << escapeJson(type) << "\": {\n";

        bool firstScope = true;
        for (const auto& [scope, users] : scopes) {
            if (!firstScope) file << ",\n";
            firstScope = false;

            file << "      \"" << escapeJson(scope) << "\": {\n";

            bool firstUser = true;
            for (const auto& [user, appList] : users) {
                if (!firstUser) file << ",\n";
                firstUser = false;

                file << "        \"" << escapeJson(user) << "\": [\n";

                for (size_t i = 0; i < appList.size(); ++i) {
                    const auto& app = appList[i];

                    file << "          {\n";
                    file << "            \"name\": \"" << escapeJson(app.name) << "\",\n";
                    file << "            \"version\": \"" << escapeJson(app.version) << "\",\n";
                    file << "            \"publisher\": \"" << escapeJson(app.publisher) << "\",\n";
                    file << "            \"install_path\": \"" << escapeJson(app.installPath) << "\",\n";
                    file << "            \"source\": {\n";
                    file << "              \"type\": \"" << escapeJson(app.source.type) << "\",\n";
                    file << "              \"location\": \"" << escapeJson(app.source.location) << "\"\n";
                    file << "            }\n";
                    file << "          }";

                    if (i + 1 < appList.size())
                        file << ",";

                    file << "\n";
                }

                file << "        ]";
            }

            file << "\n      }";
        }

        file << "\n    }";
    }

    file << "\n  }\n}\n";
    file.close();
    return true;
}
