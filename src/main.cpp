#include <exception>
#include <iostream>
#include <vector>

#include "helper/json_exporter.h"
#include "helper/normalizer.h"
#include "orchestration/scan_menu.h"
#include "orchestration/scan_plan.h"
#include "scanners/scanner_factory.h"

namespace {

int runSelectedPlan(const ScanPlan& plan) {
    std::cout << "\nRunning " << plan.name() << "...\n";

    std::vector<RawSoftwareEntry> rawEntries;
    for (const auto scannerType : plan.scanners()) {
        auto scanner = ScannerFactory::create(scannerType);
        auto entries = scanner->scan();
        rawEntries.insert(rawEntries.end(), entries.begin(), entries.end());
    }

    const Normalizer normalizer;
    const auto normalizedEntries = normalizer.normalizeAll(rawEntries);

    const JsonExporter exporter;
    exporter.exportToFile(normalizedEntries, "inventory.json");

    std::cout << "Inventory complete. Wrote " << normalizedEntries.size()
              << " normalized entries to inventory.json\n";
    return 0;
}

}  // namespace

int main() {
    try {
        const ScanMenu menu;

        while (true) {
            auto selectedPlan = menu.promptForPlan();
            if (!selectedPlan) {
                std::cout << "Exiting MABAT.\n";
                break;
            }

            runSelectedPlan(*selectedPlan);
        }

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Inventory failed: " << ex.what() << '\n';
        return 1;
    }
}
