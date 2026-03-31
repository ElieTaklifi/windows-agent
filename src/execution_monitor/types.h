#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace execution_monitor {

struct ExecutionEvent {
    std::string timestamp;
    std::string event_type;
    std::string process_name;
    std::string process_path;
    std::uint32_t pid = 0;
    std::uint32_t ppid = 0;
    std::string parent_process;
    std::string command_line;
    std::string user;
    std::string integrity_level;
    std::string source = "ETW";
    std::unordered_map<std::string, std::string> extras;
};

}  // namespace execution_monitor
