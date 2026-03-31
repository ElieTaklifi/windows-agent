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
    int choice;

    // Display the menu to the user
    std::cout << "==============================" << std::endl;
    std::cout << "          MABAT MENU          " << std::endl;
    std::cout << "==============================" << std::endl;
    std::cout << "1. Run Static Scanners" << std::endl;
    std::cout << "2. Run Dynamic Scanner" << std::endl;
    std::cout << "3. Exit" << std::endl;
    std::cout << "------------------------------" << std::endl;
    std::cout << "Enter your choice (1-3): ";

    // Get user input
    std::cin >> choice;

    // Process the response
    switch (choice) {
        case 1:
            std::cout << "\n[Action] Running Static Scanners..." << std::endl;
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
            break;

        case 2:
            std::cout << "\n[Action] Running Dynamic Scanner" << std::endl;
            // Insert your code for Option 2 here
            break;

        case 3:
            std::cout << "\nExiting program. Goodbye!" << std::endl;
            break;

        default:
            // This handles any input that isn't 1, 2, or 3
            std::cout << "\n[Error] Invalid selection. Please run the program again." << std::endl;
            break;
    }

    return 0;
}