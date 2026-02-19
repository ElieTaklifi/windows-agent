#include "json_exporter.h"

#include <fstream>
#include <stdexcept>

namespace {

std::string escapeJson(const std::string& input) {
    std::string output;
    output.reserve(input.size());

    for (const char c : input) {
        switch (c) {
            case '"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default: output += c; break;
        }
    }

    return output;
}

}  // namespace

void JsonExporter::exportToFile(const std::vector<NormalizedSoftwareEntry>& entries, const std::string& outputPath) const {
    std::ofstream out(outputPath, std::ios::out | std::ios::trunc);
    if (!out.is_open()) {
        throw std::runtime_error("Unable to open output file: " + outputPath);
    }

    out << "{\n";
    out << "  \"generatedBy\": \"Local Windows Execution Surface Inventory Engine\",\n";
    out << "  \"entries\": [\n";

    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& entry = entries[i];
        out << "    {\n";
        out << "      \"name\": \"" << escapeJson(entry.name) << "\",\n";
        out << "      \"type\": \"" << escapeJson(entry.type) << "\",\n";
        out << "      \"scope\": \"" << escapeJson(entry.scope) << "\",\n";
        out << "      \"source\": \"" << escapeJson(entry.source) << "\",\n";
        out << "      \"explanation\": \"" << escapeJson(entry.explanation) << "\",\n";
        out << "      \"userSID\": \"" << escapeJson(entry.userSID) << "\",\n";
        out << "      \"metadata\": {\n";

        size_t metadataCount = 0;
        for (const auto& [key, value] : entry.metadata) {
            out << "        \"" << escapeJson(key) << "\": \"" << escapeJson(value) << "\"";
            ++metadataCount;
            if (metadataCount < entry.metadata.size()) {
                out << ",";
            }
            out << "\n";
        }

        out << "      }\n";
        out << "    }";
        if (i + 1 < entries.size()) {
            out << ",";
        }
        out << "\n";
    }

    out << "  ]\n";
    out << "}\n";
}
