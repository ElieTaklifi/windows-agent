#include "execution_monitor/etw/etw_session_manager.h"

#include <cstring>
#include <iostream>
#include <memory>

#ifdef _WIN32
#include <Windows.h>
#include <evntrace.h>

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

EtwSessionManager* g_instance = nullptr;

}  // namespace

EtwSessionManager::EtwSessionManager() : sessionName_(L"MabatExecutionMonitor") {}

EtwSessionManager::~EtwSessionManager() {
    stop();
}

bool EtwSessionManager::start(const EventCallback& callback, bool includeImageLoads) {
    if (running_.exchange(true)) {
        return false;
    }

    callback_ = callback;
    g_instance = this;

    const ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024;
    auto properties = std::make_unique<BYTE[]>(bufferSize);
    auto* traceProps = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties.get());
    ZeroMemory(traceProps, bufferSize);

    traceProps->Wnode.BufferSize = bufferSize;
    traceProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    traceProps->Wnode.ClientContext = 1;
    traceProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    traceProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    std::memcpy(reinterpret_cast<BYTE*>(traceProps) + traceProps->LoggerNameOffset,
                sessionName_.c_str(), (sessionName_.size() + 1) * sizeof(wchar_t));

    auto status = StartTraceW(&sessionHandle_, sessionName_.c_str(), traceProps);
    if (status == ERROR_ALREADY_EXISTS) {
        ControlTraceW(0, sessionName_.c_str(), traceProps, EVENT_TRACE_CONTROL_STOP);
        status = StartTraceW(&sessionHandle_, sessionName_.c_str(), traceProps);
    }

    if (status != ERROR_SUCCESS) {
        std::cerr << "Failed to start ETW session. Error=" << status << '\n';
        running_ = false;
        return false;
    }

    if (!enableProviders(includeImageLoads)) {
        stop();
        return false;
    }

    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = const_cast<LPWSTR>(sessionName_.c_str());
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = &EtwSessionManager::eventRecordCallback;

    traceHandle_ = OpenTraceW(&logfile);
    if (traceHandle_ == INVALID_PROCESSTRACE_HANDLE) {
        std::cerr << "OpenTrace failed.\n";
        stop();
        return false;
    }

    processingThread_ = std::thread([this] {
        auto localHandle = traceHandle_;
        ProcessTrace(&localHandle, 1, nullptr, nullptr);
    });

    return true;
}

bool EtwSessionManager::enableProviders(bool includeImageLoads) {
    ENABLE_TRACE_PARAMETERS params{};
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION;

    if (EnableTraceEx2(sessionHandle_, &kKernelProcessProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                       TRACE_LEVEL_INFORMATION, 0, 0, 0, &params) != ERROR_SUCCESS) {
        std::cerr << "Failed enabling Kernel-Process provider\n";
        return false;
    }

    EnableTraceEx2(sessionHandle_, &kPowerShellProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0, 0, 0, &params);

    EnableTraceEx2(sessionHandle_, &kWmiProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0, 0, 0, &params);

    if (includeImageLoads) {
        EnableTraceEx2(sessionHandle_, &kKernelImageProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                       TRACE_LEVEL_INFORMATION, 0, 0, 0, &params);
    }

    return true;
}

void EtwSessionManager::stop() {
    if (!running_.exchange(false)) {
        return;
    }

    if (traceHandle_ != 0 && traceHandle_ != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(traceHandle_);
        traceHandle_ = 0;
    }

    if (sessionHandle_ != 0) {
        const ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024;
        auto properties = std::make_unique<BYTE[]>(bufferSize);
        auto* traceProps = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties.get());
        ZeroMemory(traceProps, bufferSize);
        traceProps->Wnode.BufferSize = bufferSize;
        traceProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(sessionHandle_, sessionName_.c_str(), traceProps, EVENT_TRACE_CONTROL_STOP);
        sessionHandle_ = 0;
    }

    if (processingThread_.joinable()) {
        processingThread_.join();
    }

    g_instance = nullptr;
}

void WINAPI EtwSessionManager::eventRecordCallback(EVENT_RECORD* record) {
    if (g_instance == nullptr || !g_instance->callback_) {
        return;
    }

    g_instance->callback_(*record);
}

}  // namespace execution_monitor

#else

namespace execution_monitor {

EtwSessionManager::EtwSessionManager() = default;
EtwSessionManager::~EtwSessionManager() = default;
bool EtwSessionManager::start(const EventCallback&, bool) { return false; }
void EtwSessionManager::stop() {}

}  // namespace execution_monitor

#endif
