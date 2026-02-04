#include "inventory.h"
#include <windows.h>
#include <iostream>

static void readUninstallKey(const char* rootPath) {
    HKEY hKey;

    if (RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            rootPath,
            0,
            KEY_READ,
            &hKey) != ERROR_SUCCESS) {
        return;
    }

    char subKeyName[256];
    DWORD subKeySize = 256;
    DWORD index = 0;

    while (RegEnumKeyExA(
               hKey,
               index,
               subKeyName,
               &subKeySize,
               nullptr,
               nullptr,
               nullptr,
               nullptr) == ERROR_SUCCESS) {

        HKEY hSubKey;
        if (RegOpenKeyExA(
                hKey,
                subKeyName,
                0,
                KEY_READ,
                &hSubKey) == ERROR_SUCCESS) {

            char displayName[512];
            DWORD size = sizeof(displayName);

            if (RegQueryValueExA(
                    hSubKey,
                    "DisplayName",
                    nullptr,
                    nullptr,
                    (LPBYTE)displayName,
                    &size) == ERROR_SUCCESS) {

                char version[128] = "";
                char publisher[256] = "";
                char installPath[512] = "";

                size = sizeof(version);
                RegQueryValueExA(hSubKey, "DisplayVersion", nullptr, nullptr, (LPBYTE)version, &size);

                size = sizeof(publisher);
                RegQueryValueExA(hSubKey, "Publisher", nullptr, nullptr, (LPBYTE)publisher, &size);

                size = sizeof(installPath);
                RegQueryValueExA(hSubKey, "InstallLocation", nullptr, nullptr, (LPBYTE)installPath, &size);

                std::cout << "Application:\n";
                std::cout << "  Name: " << displayName << "\n";
                if (*version) std::cout << "  Version: " << version << "\n";
                if (*publisher) std::cout << "  Publisher: " << publisher << "\n";
                if (*installPath) std::cout << "  Path: " << installPath << "\n";
                std::cout << "-----------------------------\n";
            }

            RegCloseKey(hSubKey);
        }

        index++;
        subKeySize = 256;
    }

    RegCloseKey(hKey);
}

static void readUninstallKeyCurrentUser(const char* rootPath) {
    HKEY hKey;

    if (RegOpenKeyExA(
            HKEY_CURRENT_USER,
            rootPath,
            0,
            KEY_READ,
            &hKey) != ERROR_SUCCESS) {
        return;
    }

    char subKeyName[256];
    DWORD subKeySize = 256;
    DWORD index = 0;

    while (RegEnumKeyExA(
               hKey,
               index,
               subKeyName,
               &subKeySize,
               nullptr,
               nullptr,
               nullptr,
               nullptr) == ERROR_SUCCESS) {

        HKEY hSubKey;
        if (RegOpenKeyExA(
                hKey,
                subKeyName,
                0,
                KEY_READ,
                &hSubKey) == ERROR_SUCCESS) {

            char displayName[512];
            DWORD size = sizeof(displayName);

            if (RegQueryValueExA(
                    hSubKey,
                    "DisplayName",
                    nullptr,
                    nullptr,
                    (LPBYTE)displayName,
                    &size) == ERROR_SUCCESS) {

                char version[128] = "";
                char publisher[256] = "";
                char installPath[512] = "";

                size = sizeof(version);
                RegQueryValueExA(hSubKey, "DisplayVersion", nullptr, nullptr, (LPBYTE)version, &size);

                size = sizeof(publisher);
                RegQueryValueExA(hSubKey, "Publisher", nullptr, nullptr, (LPBYTE)publisher, &size);

                size = sizeof(installPath);
                RegQueryValueExA(hSubKey, "InstallLocation", nullptr, nullptr, (LPBYTE)installPath, &size);

                std::cout << "Application:\n";
                std::cout << "  Name: " << displayName << "\n";
                if (*version) std::cout << "  Version: " << version << "\n";
                if (*publisher) std::cout << "  Publisher: " << publisher << "\n";
                if (*installPath) std::cout << "  Path: " << installPath << "\n";
                std::cout << "-----------------------------\n";
            }

            RegCloseKey(hSubKey);
        }

        index++;
        subKeySize = 256;
    }

    RegCloseKey(hKey);
}

void enumerateInstalledApplications() {
    readUninstallKey("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    readUninstallKey("Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    
    //Need to check for this path but for all the user /+ mention wich user
    readUninstallKeyCurrentUser("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    
    //need to add HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall
    //need to add Microsoft Store (UWP / MSIX) apps using powershell Get-AppxPackage
    // Drivers and kernel components: HKLM\SYSTEM\CurrentControlSet\Services
    // Services installed manually
    // Scheduled-task–based persistence Software launched via: Task Scheduler, startup folder, Registry Run keys -> None require uninstall registration.
    // MSI edge cases : Some MSI packages:Suppress ARP entries Use ARPSYSTEMCOMPONENT=1 Result: installed, but hidden.

}
