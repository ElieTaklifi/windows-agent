#include "execution_monitor/output/jsonl_writer.h"

#include <chrono>
#include <iomanip>
#include <sstream>

namespace execution_monitor {

JsonlWriter::JsonlWriter(std::filesystem::path outputPath, const std::size_t maxBytes)
    : outputPath_(std::move(outputPath)), maxBytes_(maxBytes) {}

void JsonlWriter::write(const ExecutionEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensureOpen();
    rotateIfNeeded();
    out_ << toJsonLine(event) << '\n';
    out_.flush();
}

void JsonlWriter::ensureOpen() {
    if (out_.is_open()) {
        return;
    }

    std::filesystem::create_directories(outputPath_.parent_path());
    out_.open(outputPath_, std::ios::app);
}

void JsonlWriter::rotateIfNeeded() {
    if (!std::filesystem::exists(outputPath_)) {
        return;
    }

    const auto fileSize = std::filesystem::file_size(outputPath_);
    if (fileSize < maxBytes_) {
        return;
    }

    out_.close();

    const auto now = std::chrono::system_clock::now();
    const auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif

    std::ostringstream suffix;
    suffix << std::put_time(&tm, "%Y%m%d%H%M%S");

    auto rotatedPath = outputPath_;
    rotatedPath += "." + suffix.str();
    std::filesystem::rename(outputPath_, rotatedPath);

    out_.open(outputPath_, std::ios::app);
}

std::string JsonlWriter::toJsonLine(const ExecutionEvent& event) const {
    std::ostringstream ss;
    ss << '{'
       << "\"timestamp\":\"" << escapeJson(event.timestamp) << "\"," 
       << "\"event_type\":\"" << escapeJson(event.event_type) << "\"," 
       << "\"process_name\":\"" << escapeJson(event.process_name) << "\"," 
       << "\"process_path\":\"" << escapeJson(event.process_path) << "\"," 
       << "\"pid\":" << event.pid << ','
       << "\"ppid\":" << event.ppid << ','
       << "\"parent_process\":\"" << escapeJson(event.parent_process) << "\"," 
       << "\"command_line\":\"" << escapeJson(event.command_line) << "\"," 
       << "\"user\":\"" << escapeJson(event.user) << "\"," 
       << "\"integrity_level\":\"" << escapeJson(event.integrity_level) << "\"," 
       << "\"source\":\"" << escapeJson(event.source) << '\"';

    for (const auto& [k, v] : event.extras) {
        ss << ",\"" << escapeJson(k) << "\":\"" << escapeJson(v) << '\"';
    }

    ss << '}';
    return ss.str();
}

std::string JsonlWriter::escapeJson(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size());

    for (const char c : value) {
        switch (c) {
            case '\\':
                escaped += "\\\\";
                break;
            case '\"':
                escaped += "\\\"";
                break;
            case '\n':
                escaped += "\\n";
                break;
            case '\r':
                escaped += "\\r";
                break;
            case '\t':
                escaped += "\\t";
                break;
            default:
                escaped += c;
                break;
        }
    }

    return escaped;
}

}  // namespace execution_monitor
