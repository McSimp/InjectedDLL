#pragma once

#include <string>
#include <PolyHook/PolyHook.h>
#include "ModuleScan.h"

namespace Util
{
    std::wstring Widen(const std::string& input);
    std::string Narrow(const std::wstring& input);
    std::string DataToHex(const char* input, size_t len);
    void HookLibraryFunction(PLH::Detour& detour, const std::string& module, const std::string& funcName, void* hookFunc);
    void* HookSignatureFunction(PLH::Detour& detour, ModuleScan& scanner, const char* sig, const char* mask, void* hookFunc);
    void* ResolveLibraryFunction(const std::string& module, const std::string& funcName);
}
