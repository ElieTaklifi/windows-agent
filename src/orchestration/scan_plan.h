#pragma once

#include <string>
#include <utility>
#include <vector>

#include "../scanners/scanner_factory.h"

class ScanPlan {
public:
    virtual ~ScanPlan() = default;

    virtual std::string name() const = 0;
    virtual std::vector<ScannerType> scanners() const = 0;
};

class GeneralScanPlan final : public ScanPlan {
public:
    std::string name() const override {
        return "General scan";
    }

    std::vector<ScannerType> scanners() const override {
        return {
            ScannerType::Registry,
            ScannerType::Autorun,
            ScannerType::Filesystem,
            ScannerType::OSCatalog,
            ScannerType::Service,
        };
    }
};

class DeepScanPlan final : public ScanPlan {
public:
    std::string name() const override {
        return "Very deep scan";
    }

    std::vector<ScannerType> scanners() const override {
        return {
            ScannerType::Registry,
            ScannerType::Autorun,
            ScannerType::Filesystem,
            ScannerType::OSCatalog,
            ScannerType::Persistence,
            ScannerType::Service,
        };
    }
};

class SingleScannerPlan final : public ScanPlan {
public:
    explicit SingleScannerPlan(ScannerDescriptor scanner)
        : scanner_(std::move(scanner)) {
    }

    std::string name() const override {
        return "Single scanner: " + scanner_.name;
    }

    std::vector<ScannerType> scanners() const override {
        return {scanner_.type};
    }

private:
    ScannerDescriptor scanner_;
};
