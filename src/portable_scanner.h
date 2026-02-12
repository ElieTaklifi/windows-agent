#pragma once
#include <string>
#include "json_builder.h"

class PortableScanner {
public:
    static void scan(JsonBuilder& json);

private:
    static void scanDirectory(
        const std::wstring& basePath,
        const std::wstring& userName,
        JsonBuilder& json
    );

    static bool isExecutable(const std::wstring& filename);
    static std::string toUtf8(const std::wstring& w);
};
