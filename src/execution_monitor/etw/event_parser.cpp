#include "execution_monitor/etw/event_parser.h"

#ifdef _WIN32

#include <Windows.h>
#include <sddl.h>
#include <tdh.h>
#include <psapi.h>

#include <array>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>

#pragma comment(lib, "tdh.lib")

namespace execution_monitor {
namespace {

constexpr GUID kKernelProcessProvider =
    {0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};
constexpr GUID kPowerShellProvider =
    {0xa0c1853b, 0x5c40, 0x4b15, {0x87, 0x6c, 0x3c, 0xf1, 0xc5, 0x8f, 0x98, 0x53}};
constexpr GUID kWmiProvider =
    {0x1418ef04, 0xb0b4, 0x4623, {0xbf, 0x7e, 0xd7, 0x4a, 0xb4, 0x7b, 0xbd, 0xaa}};
constexpr GUID kKernelImageProvider =
    {0x2cb15d1d, 0x5fc1, 0x11d2, {0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18}};

std::string narrow(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }

    std::string out(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, out.data(), size, nullptr, nullptr);
    return out;
}

std::string isoTimestamp(const FILETIME& ft) {
    SYSTEMTIME utc{};
    FileTimeToSystemTime(&ft, &utc);
    std::ostringstream ss;
    ss << std::setfill('0')
       << std::setw(4) << utc.wYear << '-'
       << std::setw(2) << utc.wMonth << '-'
       << std::setw(2) << utc.wDay << 'T'
       << std::setw(2) << utc.wHour << ':'
       << std::setw(2) << utc.wMinute << ':'
       << std::setw(2) << utc.wSecond << 'Z';
    return ss.str();
}

std::string integrityToText(DWORD rid) {
    if (rid >= SECURITY_MANDATORY_SYSTEM_RID) return "System";
    if (rid >= SECURITY_MANDATORY_HIGH_RID) return "High";
    if (rid >= SECURITY_MANDATORY_MEDIUM_RID) return "Medium";
    if (rid >= SECURITY_MANDATORY_LOW_RID) return "Low";
    return "Untrusted";
}

std::wstring getPropertyString(const EVENT_RECORD& record, const wchar_t* name) {
    PROPERTY_DATA_DESCRIPTOR descriptor{};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
    descriptor.ArrayIndex = ULONG_MAX;

    ULONG size = 0;
    if (TdhGetPropertySize(&record, 0, nullptr, 1, &descriptor, &size) != ERROR_SUCCESS || size == 0) {
        return L"";
    }

    std::wstring data(size / sizeof(wchar_t), L'\0');
    if (TdhGetProperty(&record, 0, nullptr, 1, &descriptor, size, reinterpret_cast<PBYTE>(data.data())) != ERROR_SUCCESS) {
        return L"";
    }

    const auto nullPos = data.find(L'\0');
    if (nullPos != std::wstring::npos) {
        data.resize(nullPos);
    }
    return data;
}

std::string getUserFromPid(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        return "";
    }

    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        CloseHandle(process);
        return "";
    }

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
        CloseHandle(token);
        CloseHandle(process);
        return "";
    }

    auto* tokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
    wchar_t name[256];
    wchar_t domain[256];
    DWORD nameLen = 256, domainLen = 256;
    SID_NAME_USE use;
    std::string result;
    if (LookupAccountSidW(nullptr, tokenUser->User.Sid, name, &nameLen, domain, &domainLen, &use)) {
        result = narrow(std::wstring(domain) + L"\\" + name);
    }

    CloseHandle(token);
    CloseHandle(process);
    return result;
}

std::string getIntegrityFromPid(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        return "";
    }

    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        CloseHandle(process);
        return "";
    }

    DWORD size = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), size, &size)) {
        CloseHandle(token);
        CloseHandle(process);
        return "";
    }

    const auto* integrity = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data());
    const DWORD rid = *GetSidSubAuthority(integrity->Label.Sid,
                                          static_cast<DWORD>(*GetSidSubAuthorityCount(integrity->Label.Sid) - 1));

    CloseHandle(token);
    CloseHandle(process);
    return integrityToText(rid);
}

std::string getImageNameFromPid(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        return "";
    }

    wchar_t path[MAX_PATH * 4];
    DWORD size = static_cast<DWORD>(std::size(path));
    std::string out;
    if (QueryFullProcessImageNameW(process, 0, path, &size)) {
        out = narrow(std::wstring(path, size));
    }

    CloseHandle(process);
    return out;
}

std::string basenameFromPath(const std::string& path) {
    const auto pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

}  // namespace

std::optional<ExecutionEvent> EventParser::parse(const EVENT_RECORD& record) const {
    ExecutionEvent event;
    event.timestamp = isoTimestamp(record.EventHeader.TimeStamp);
    event.pid = record.EventHeader.ProcessId;

    const auto& providerId = record.EventHeader.ProviderId;

    if (providerId == kKernelProcessProvider && record.EventHeader.EventDescriptor.Opcode == 1) {
        event.event_type = "process_start";
        event.process_path = narrow(getPropertyString(record, L"ImageFileName"));
        if (event.process_path.empty()) {
            event.process_path = getImageNameFromPid(event.pid);
        }
        event.process_name = basenameFromPath(event.process_path);
        event.command_line = narrow(getPropertyString(record, L"CommandLine"));

        const auto ppidText = narrow(getPropertyString(record, L"ParentProcessID"));
        if (!ppidText.empty()) {
            event.ppid = static_cast<std::uint32_t>(std::strtoul(ppidText.c_str(), nullptr, 10));
        }

        event.parent_process = basenameFromPath(getImageNameFromPid(event.ppid));
        event.user = getUserFromPid(event.pid);
        event.integrity_level = getIntegrityFromPid(event.pid);
        return event;
    }

    if (providerId == kPowerShellProvider) {
        event.event_type = "powershell_activity";
        event.process_path = getImageNameFromPid(event.pid);
        event.process_name = basenameFromPath(event.process_path);
        event.command_line = narrow(getPropertyString(record, L"CommandLine"));
        event.extras["script_block"] = narrow(getPropertyString(record, L"ScriptBlockText"));
        event.user = getUserFromPid(event.pid);
        event.integrity_level = getIntegrityFromPid(event.pid);
        return event;
    }

    if (providerId == kWmiProvider) {
        event.event_type = "wmi_activity";
        event.process_path = getImageNameFromPid(event.pid);
        event.process_name = basenameFromPath(event.process_path);
        event.extras["operation"] = narrow(getPropertyString(record, L"Operation"));
        event.extras["query"] = narrow(getPropertyString(record, L"Query"));
        event.user = getUserFromPid(event.pid);
        event.integrity_level = getIntegrityFromPid(event.pid);
        return event;
    }

    if (providerId == kKernelImageProvider) {
        event.event_type = "module_load";
        event.process_path = getImageNameFromPid(event.pid);
        event.process_name = basenameFromPath(event.process_path);
        event.extras["module_path"] = narrow(getPropertyString(record, L"ImageName"));
        event.user = getUserFromPid(event.pid);
        event.integrity_level = getIntegrityFromPid(event.pid);
        return event;
    }

    return std::nullopt;
}

}  // namespace execution_monitor

#endif
