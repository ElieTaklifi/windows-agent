#pragma once

#include <memory>
#include <string>
#include <vector>

#include "idiscovery_scanner.h"

enum class ScannerType {
    Registry,
    Autorun,
    Filesystem,
    OSCatalog,
    Persistence,
    Service,
};

struct ScannerDescriptor {
    ScannerType type;
    std::string name;
    std::string description;
};

class ScannerFactory {
public:
    static std::unique_ptr<IDiscoveryScanner> create(ScannerType type);
    static std::vector<ScannerDescriptor> availableScanners();
};
