#pragma once

#include "json_builder.h"

#include <windows.h>

class UwpScanner {
public:
    static void scan(JsonBuilder& json);

private:
    static bool readRegString(HKEY hKey,const std::wstring& valueName,std::wstring& out);
    static void splitPackageName(const std::wstring& fullName,std::wstring& name,std::wstring& version); 
};