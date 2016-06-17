#include <locale>
#include <codecvt>
#include "Util.h"
#include <Windows.h>
#include <spdlog/spdlog.h>

namespace Util
{
    // Taken from https://stackoverflow.com/a/18374698
    std::wstring Widen(const std::string& input)
    {
        using convert_typeX = std::codecvt_utf8<wchar_t>;
        std::wstring_convert<convert_typeX, wchar_t> converterX;
        return converterX.from_bytes(input);
    }

    // Taken from https://stackoverflow.com/a/18374698
    std::string Narrow(const std::wstring& input)
    {
        using convert_typeX = std::codecvt_utf8<wchar_t>;
        std::wstring_convert<convert_typeX, wchar_t> converterX;
        return converterX.to_bytes(input);
    }

    // This will convert some data like "Hello World" to "48 65 6C 6C 6F 20 57 6F 72 6C 64"
    // Taken mostly from https://stackoverflow.com/a/3382894
    std::string DataToHex(const char* input, size_t len)
    {
        static const char* const lut = "0123456789ABCDEF";

        std::string output;
        output.reserve(2 * len);
        for (size_t i = 0; i < len; i++)
        {
            const unsigned char c = input[i];
            output.push_back(lut[c >> 4]);
            output.push_back(lut[c & 15]);
        }

        return output;
    }

    void HookLibraryFunction(PLH::Detour& detour, const std::string& module, const std::string& funcName, void* hookFunc)
    {
        HMODULE hModule = GetModuleHandle(Util::Widen(module).c_str());
        if (!hModule)
        {
            throw std::runtime_error(fmt::sprintf("GetModuleHandle failed for %s (Error = 0x%X)", module, GetLastError()));
        }

        FARPROC funcAddr = GetProcAddress(hModule, funcName.c_str());
        if (!funcAddr)
        {
            throw std::runtime_error(fmt::sprintf("GetProcAddress failed for %s (Error = 0x%X)", funcName, GetLastError()));
        }

        detour.SetupHook((BYTE*)funcAddr, (BYTE*)hookFunc);

        if (!detour.Hook())
        {
            PLH::RuntimeError err = detour.GetLastError();
            throw std::runtime_error(fmt::sprintf("Hook failed for %s: %s", funcName, err.GetString()));
        }
    }

    void* HookSignatureFunction(PLH::Detour& detour, ModuleScan& scanner, const char* sig, const char* mask, void* hookFunc)
    {
        int sigLen = strlen(mask);
        void* sigAddr = scanner.Scan(sig, mask, sigLen);

        detour.SetupHook((BYTE*)sigAddr, (BYTE*)hookFunc);

        if (!detour.Hook())
        {
            PLH::RuntimeError err = detour.GetLastError();
            throw std::runtime_error(fmt::sprintf("Hook failed for signature %s: %s", Util::DataToHex(sig, sigLen), err.GetString()));
        }

        return sigAddr;
    }
}
