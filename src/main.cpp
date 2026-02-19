#include <exception>
#include <iostream>
#include <memory>
#include <vector>



#include "helper/json_exporter.h"
#include "helper/normalizer.h"

#include "scanners/idiscovery_scanner.h"
#include "scanners/registry_scanner.h"
#include "scanners/autorun_scanner.h"
#include "scanners/filesystem_scanner.h"
#include "scanners/os_catalog_scanner.h"
#include "scanners/persistence_scanner.h"

int main() {
    try {
        std::vector<std::unique_ptr<IDiscoveryScanner>> scanners;
        scanners.push_back(std::make_unique<RegistryScanner>());
        scanners.push_back(std::make_unique<AutorunScanner>());
        //scanners.push_back(std::make_unique<FilesystemScanner>());
        //scanners.push_back(std::make_unique<OSCatalogScanner>());
        //scanners.push_back(std::make_unique<PersistenceScanner>());

        std::vector<RawSoftwareEntry> rawEntries;
        for (const auto& scanner : scanners) {
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
    } catch (const std::exception& ex) {
        std::cerr << "Inventory failed: " << ex.what() << '\n';
        return 1;
    }
}
