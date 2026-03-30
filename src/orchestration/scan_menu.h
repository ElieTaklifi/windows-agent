#pragma once

#include <memory>

#include "scan_plan.h"

class ScanMenu {
public:
    std::unique_ptr<ScanPlan> promptForPlan() const;

private:
    static int promptForChoice(int min, int max);
    std::unique_ptr<ScanPlan> promptForSingleScannerPlan() const;
};
