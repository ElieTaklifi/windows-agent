#include "scanner_factory.h"

#include <stdexcept>

#include "autorun_scanner.h"
#include "filesystem_scanner.h"
#include "os_catalog_scanner.h"
#include "persistence_scanner.h"
#include "registry_scanner.h"
#include "service_scanner.h"

std::unique_ptr<IDiscoveryScanner> ScannerFactory::create(ScannerType type) {
    switch (type) {
        case ScannerType::Registry:
            return std::make_unique<RegistryScanner>();
        case ScannerType::Autorun:
            return std::make_unique<AutorunScanner>();
        case ScannerType::Filesystem:
            return std::make_unique<FilesystemScanner>();
        case ScannerType::OSCatalog:
            return std::make_unique<OSCatalogScanner>();
        case ScannerType::Persistence:
            return std::make_unique<PersistenceScanner>();
        case ScannerType::Service:
            return std::make_unique<ServiceScanner>();
        default:
            throw std::invalid_argument("Unknown scanner type requested.");
    }
}

std::vector<ScannerDescriptor> ScannerFactory::availableScanners() {
    return {
        {ScannerType::Registry, "RegistryScanner", "Installed software from uninstall and MSI metadata."},
        {ScannerType::Autorun, "AutorunScanner", "Autorun registry entries (Run/RunOnce/RunOnceEx)."},
        {ScannerType::Filesystem, "FilesystemScanner", "Executable discovery in Program Files locations."},
        {ScannerType::OSCatalog, "OSCatalogScanner", "AppX/UWP package catalog entries."},
        {ScannerType::Persistence, "PersistenceScanner", "Startup folders and selected persistence artifacts."},
        {ScannerType::Service, "ServiceScanner", "Windows services and drivers from Services registry hive."},
    };
}
