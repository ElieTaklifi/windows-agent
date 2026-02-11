#include "portable_scanner.h"
#include <windows.h>
#include <filesystem>

namespace fs = std::filesystem;

bool PortableScanner::isExecutable(const std::wstring& filename) {
    static const wchar_t* exts[] = {
        L".exe", L".dll", L".ps1", L".bat", L".cmd"
    };

    for (const auto& ext : exts) {
        if (filename.size() >= wcslen(ext) &&
            _wcsicmp(filename.c_str() + filename.size() - wcslen(ext), ext) == 0) {
            return true;
        }
    }
    return false;
}

void PortableScanner::scanDirectory(
    const std::wstring& basePath,
    const std::wstring& userName,
    JsonBuilder& json
) {
    try {
        if (!fs::exists(basePath))
            return;

        for (const auto& entry : fs::recursive_directory_iterator(
                 basePath,
                 fs::directory_options::skip_permission_denied)) {

            if (!entry.is_regular_file())
                continue;

            const auto& path = entry.path();
            if (!isExecutable(path.filename().wstring()))
                continue;

            ApplicationRecord app;
            app.type = "portable";
            app.scope = "Observed";
            app.user = std::string(userName.begin(), userName.end());
            app.name = path.filename().string();
            app.version = "";
            app.publisher = "";
            app.installPath = path.string();
            
            app.source.type = "filesystem";
            app.source.location = basePath;

            json.addApplication(app);
        }
    }
    catch (...) {
        // Intentionally silent: inventory must never crash the agent
    }
}

void PortableScanner::scan(JsonBuilder& json) {
    // System-wide paths
    scanDirectory(L"C:\\Tools", L"SYSTEM", json);
    scanDirectory(L"C:\\ProgramData", L"SYSTEM", json);

    // Per-user paths
    const std::wstring usersRoot = L"C:\\Users";

    for (const auto& userDir : fs::directory_iterator(usersRoot)) {
        if (!userDir.is_directory())
            continue;

        const auto userName = userDir.path().filename().wstring();

        scanDirectory(userDir.path().wstring() + L"\\Downloads", userName, json);
        scanDirectory(userDir.path().wstring() + L"\\Desktop", userName, json);
    }
}
