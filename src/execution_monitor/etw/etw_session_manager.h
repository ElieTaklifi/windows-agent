#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>

#ifdef _WIN32
#include <evntrace.h>
#else
struct EVENT_RECORD;
#endif

namespace execution_monitor {

class EtwSessionManager {
public:
    using EventCallback = std::function<void(const EVENT_RECORD&)>;

    EtwSessionManager();
    ~EtwSessionManager();

    bool start(const EventCallback& callback, bool includeImageLoads);
    void stop();

private:
#ifdef _WIN32
    static void WINAPI eventRecordCallback(EVENT_RECORD* record);
    bool enableProviders(bool includeImageLoads);

    TRACEHANDLE sessionHandle_ = 0;
    TRACEHANDLE traceHandle_ = 0;
    std::thread processingThread_;
    std::wstring sessionName_;
#endif

    std::atomic<bool> running_{false};
    EventCallback callback_;
};

}  // namespace execution_monitor
