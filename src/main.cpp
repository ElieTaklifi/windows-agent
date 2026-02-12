#include <iostream>

#include "inventory.h"
#include "json_builder.h"
#include "portable_scanner.h"

int main() {
    JsonBuilder builder;

    enumerateInstalledApplications(builder);
    enumerateUwpPackages(builder);

    PortableScanner scanner;
    scanner.scan(builder);

    if (builder.writeToFile("inventory.json")) {
        std::cout << "Inventory written to inventory.json\n";
    } else {
        std::cerr << "Failed to write inventory file\n";
    }

    return 0;
}
