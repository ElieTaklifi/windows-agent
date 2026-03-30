#include "scan_menu.h"

#include <iostream>
#include <limits>

#include "../scanners/scanner_factory.h"

int ScanMenu::promptForChoice(int min, int max) {
    while (true) {
        int choice = 0;
        std::cin >> choice;

        if (!std::cin.fail() && choice >= min && choice <= max) {
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            return choice;
        }

        std::cout << "Invalid choice. Enter a number between " << min << " and " << max << ": ";
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
}

std::unique_ptr<ScanPlan> ScanMenu::promptForSingleScannerPlan() const {
    const auto scanners = ScannerFactory::availableScanners();

    std::cout << "\nChoose scanner to run:\n";
    for (size_t i = 0; i < scanners.size(); ++i) {
        std::cout << "  " << (i + 1) << ") " << scanners[i].name << " - " << scanners[i].description << "\n";
    }
    std::cout << "Choice: ";

    const int choice = promptForChoice(1, static_cast<int>(scanners.size()));
    return std::make_unique<SingleScannerPlan>(scanners[static_cast<size_t>(choice - 1)]);
}

std::unique_ptr<ScanPlan> ScanMenu::promptForPlan() const {
    std::cout << "\n=== MABAT Scan Menu ===\n"
              << "  1) Run a specific scanner\n"
              << "  2) Run general scan\n"
              << "  3) Run very deep scan\n"
              << "  4) Exit\n"
              << "Choice: ";

    const int choice = promptForChoice(1, 4);

    switch (choice) {
        case 1:
            return promptForSingleScannerPlan();
        case 2:
            return std::make_unique<GeneralScanPlan>();
        case 3:
            return std::make_unique<DeepScanPlan>();
        case 4:
            return nullptr;
        default:
            return nullptr;
    }
}
