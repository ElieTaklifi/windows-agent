#pragma once

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>

#include "execution_monitor/types.h"

namespace execution_monitor {

class JsonlWriter {
public:
    JsonlWriter(std::filesystem::path outputPath, std::size_t maxBytes);

    void write(const ExecutionEvent& event);

private:
    void ensureOpen();
    void rotateIfNeeded();
    std::string toJsonLine(const ExecutionEvent& event) const;
    static std::string escapeJson(const std::string& value);

    std::filesystem::path outputPath_;
    std::size_t maxBytes_;
    std::ofstream out_;
    std::mutex mutex_;
};

}  // namespace execution_monitor
