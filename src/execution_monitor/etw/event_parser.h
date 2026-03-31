#pragma once

#include <optional>

#include "execution_monitor/types.h"

#ifdef _WIN32
#include <evntcons.h>
#endif

namespace execution_monitor {

class EventParser {
public:
#ifdef _WIN32
    std::optional<ExecutionEvent> parse(const EVENT_RECORD& record) const;
#endif
};

}  // namespace execution_monitor
