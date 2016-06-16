#pragma once

#include <string>
#include <PolyHook/PolyHook.h>

namespace Util
{
    std::wstring Widen(const std::string& input);
    std::string Narrow(const std::wstring& input);
    std::string DataToHex(const char* input, size_t len);
    void HookRuntimeFunction(PLH::Detour& detour, const std::string& module, const std::string& funcName, void* hookFunc);
}
