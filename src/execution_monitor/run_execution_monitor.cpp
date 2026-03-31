#include "execution_monitor/run_execution_monitor.h"

#include <atomic>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <thread>

#include "execution_monitor/etw/etw_session_manager.h"
#include "execution_monitor/etw/event_parser.h"
#include "execution_monitor/output/jsonl_writer.h"
#include "execution_monitor/utils/thread_safe_queue.h"

namespace {
std::atomic<bool> g_stopRequested{false};

void signalHandler(int) {
    g_stopRequested = true;
}
}  // namespace

void run_execution_monitor() {
#ifndef _WIN32
    std::cerr << "Execution monitor is Windows-only and requires ETW support.\n";
    return;
#else
    std::cout << "Starting execution monitor (ETW). Press Ctrl+C to stop.\n";

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    execution_monitor::ThreadSafeQueue<execution_monitor::ExecutionEvent> queue;
    execution_monitor::JsonlWriter writer(R"(C:\ProgramData\Agent\execution_events.jsonl)",
                                          25 * 1024 * 1024);
    execution_monitor::EventParser parser;
    execution_monitor::EtwSessionManager manager;

    std::thread writerThread([&] {
        while (!g_stopRequested.load()) {
            auto event = queue.waitAndPop();
            if (!event.has_value()) {
                break;
            }
            writer.write(*event);
        }
    });

    const bool started = manager.start(
        [&](const EVENT_RECORD& record) {
            auto parsed = parser.parse(record);
            if (parsed.has_value()) {
                queue.push(std::move(*parsed));
            }
        },
        true);

    if (!started) {
        std::cerr << "Failed to initialize ETW monitoring session.\n";
        g_stopRequested = true;
    }

    while (!g_stopRequested.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    manager.stop();
    queue.stop();

    if (writerThread.joinable()) {
        writerThread.join();
    }

    std::cout << "Execution monitor stopped. Output: C:\\ProgramData\\Agent\\execution_events.jsonl\n";
#endif
}
