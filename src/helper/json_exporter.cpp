#include "json_exporter.h"

#include <fstream>
#include <stdexcept>

namespace {

// Extended escaper: handles control chars and embedded NUL that appear
// in real registry values on some systems.
std::string escapeJson(const std::string& input) {
    std::string output;
    output.reserve(input.size() + 8);
    for (const unsigned char c : input) {
        switch (c) {
            case '"':  output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\n': output += "\\n";  break;
            case '\r': output += "\\r";  break;
            case '\t': output += "\\t";  break;
            case '\0': break;  // drop embedded NUL
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", unsigned(c));
                    output += buf;
                } else {
                    output += char(c);
                }
        }
    }
    return output;
}

}  // namespace

void JsonExporter::exportToFile(
    const std::vector<NormalizedSoftwareEntry>& entries,
    const std::string& outputPath) const
{
    std::ofstream out(outputPath, std::ios::out | std::ios::trunc);
    if (!out.is_open())
        throw std::runtime_error("Unable to open output file: " + outputPath);

    out << "{\n";
    out << "  \"generatedBy\": \"Local Windows Execution Surface Inventory Engine\",\n";
    out << "  \"entryCount\": " << entries.size() << ",\n";
    out << "  \"entries\": [\n";

    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];
        out << "    {\n";
        out << "      \"name\": \""            << escapeJson(e.name)            << "\",\n";
        out << "      \"type\": \""            << escapeJson(e.type)            << "\",\n";
        out << "      \"scope\": \""           << escapeJson(e.scope)           << "\",\n";
        out << "      \"source\": \""          << escapeJson(e.source)          << "\",\n";
        out << "      \"severity\": \""        << escapeJson(e.severity)        << "\",\n";
        out << "      \"severityReasons\": \"" << escapeJson(e.severityReasons) << "\",\n";
        out << "      \"explanation\": \""     << escapeJson(e.explanation)     << "\",\n";
        out << "      \"userSID\": \""         << escapeJson(e.userSID)         << "\",\n";
        out << "      \"metadata\": {\n";

        size_t mc = 0;
        for (const auto& [key, value] : e.metadata) {
            out << "        \"" << escapeJson(key) << "\": \"" << escapeJson(value) << "\"";
            if (++mc < e.metadata.size()) out << ",";
            out << "\n";
        }

        out << "      }\n";
        out << "    }";
        if (i + 1 < entries.size()) out << ",";
        out << "\n";
    }

    out << "  ]\n";
    out << "}\n";
}
